"""Scoring of detection decisions against independently generated ground truth.

Primary unit: (prefix, window) -- the non-overlapping units the detector
classified. Ground truth for a unit comes only from the generated packets
(experiments/phase4/netsim.Truth), never from telemetry:

    attack unit  = the prefix holds >= 1 packet of a malicious flow in the window
    clean unit   = it holds none (including units with no true traffic at all)
    mixed unit   = attack unit that also holds benign traffic

    TP flagged & attack   FP flagged & clean   FN benign & attack   TN benign & clean
    Abstained units are counted separately and never as TN or FN.

Host level (attacker identification): only /32 decisions identify a host.
    identified   attacker host-window flagged by a /32 unit (TP_h)
    false_ident  benign host flagged by a /32 unit (FP_h)
    unresolved   attacker host-window inside a flagged coarser unit (detected, not identified)
    missed       attacker host-window not inside any flagged unit and not abstained
    abstained    attacker host-window inside an abstained unit
    collateral   benign host-window inside a flagged coarser unit (would be hit by
                 prefix-level mitigation)
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from aggregator.detection import ABSTAIN, MAL_AMBIGUOUS, MAL_HOST, Decision
from experiments.phase4.netsim import Truth


@dataclass
class UnitTruth:
    attack_pkts: int
    benign_pkts: int
    attacker_hosts: set
    benign_hosts: set

    @property
    def attack(self) -> bool:
        return self.attack_pkts > 0

    @property
    def mixed(self) -> bool:
        return self.attack_pkts > 0 and self.benign_pkts > 0


def unit_truth(truth: Truth, window: int, prefix: str, length: int) -> UnitTruth:
    cache = truth.__dict__.setdefault("_unit_cache", {})     # truth is immutable once built
    key = (window, prefix, length)
    if key not in cache:
        cache[key] = _unit_truth(truth, window, prefix, length)
    return cache[key]


def _unit_truth(truth: Truth, window: int, prefix: str, length: int) -> UnitTruth:
    net = ipaddress.IPv4Network(f"{prefix}/{length}", strict=False)
    atk = ben = 0
    atk_hosts, ben_hosts = set(), set()
    for total, attack in ((truth.fwd[window], truth.atk_fwd[window]),
                          (truth.rev[window], truth.atk_rev[window])):
        for addr, n in total.items():
            if ipaddress.IPv4Address(addr) not in net:
                continue
            a = attack.get(addr, 0)
            atk += a
            ben += n - a
            if a:
                atk_hosts.add(addr)
            if n - a:
                ben_hosts.add(addr)
    return UnitTruth(atk, ben, atk_hosts, ben_hosts)


def _ratio(num: int, den: int) -> Optional[float]:
    return num / den if den else None


def score(decisions: Iterable[Decision], truth: Truth, lag: int, windows: range,
          windows_with_traffic: Optional[int] = None) -> Dict:
    """`lag`: truth window = decision window - lag (1 for arrival-aligned methods)."""
    tp = fp = tn = fn = 0
    abst = abst_attack = 0
    flagged_mixed = flagged_ambiguous = 0
    h_ident = h_false = h_unres = h_missed = h_abst = h_collat = 0
    classified_windows, abstained_windows = set(), set()
    attacker_hw_seen = set()
    per_window: Dict[int, List[Decision]] = {}
    for d in decisions:
        tw = d.window - lag
        if tw not in windows:
            continue
        per_window.setdefault(tw, []).append(d)

    for tw, ds in per_window.items():
        flagged_hosts, unres_hosts, abst_hosts = set(), set(), set()
        for d in ds:
            ut = unit_truth(truth, tw, d.prefix, d.length)
            if d.label == ABSTAIN:
                abst += 1
                abst_attack += ut.attack
                abstained_windows.add(tw)
                abst_hosts |= ut.attacker_hosts
                continue
            classified_windows.add(tw)
            if d.flagged:
                if ut.attack:
                    tp += 1
                else:
                    fp += 1
                flagged_mixed += ut.mixed
                if d.label == MAL_AMBIGUOUS:
                    flagged_ambiguous += 1
                    unres_hosts |= ut.attacker_hosts
                    h_collat += len(ut.benign_hosts)
                else:  # MAL_HOST: a /32 identifies exactly one address
                    if ut.attacker_hosts:
                        flagged_hosts |= ut.attacker_hosts
                    elif ut.benign_hosts or not ut.attack:
                        h_false += 1
            else:
                if ut.attack:
                    fn += 1
                else:
                    tn += 1
        # Host-level accounting against every attacker host active in this window.
        active = {a for a, n in truth.atk_fwd[tw].items() if n} | {a for a, n in truth.atk_rev[tw].items() if n}
        for host in active:
            attacker_hw_seen.add((tw, host))
            if host in flagged_hosts:
                h_ident += 1
            elif host in unres_hosts:
                h_unres += 1
            elif host in abst_hosts:
                h_abst += 1
            else:
                h_missed += 1

    classified = tp + fp + tn + fn
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and (precision + recall) > 0 else None)
    wt = windows_with_traffic if windows_with_traffic is not None else len(per_window)
    return {
        "units_classified": classified, "units_abstained": abst,
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "precision": precision, "precision_den": f"{tp}/{tp + fp}",
        "recall_detection_rate": recall, "recall_den": f"{tp}/{tp + fn}",
        "f1": f1,
        "fpr": _ratio(fp, fp + tn), "fpr_den": f"{fp}/{fp + tn}",
        "abstention_rate": _ratio(abst, abst + classified), "abstention_den": f"{abst}/{abst + classified}",
        "abstained_units_with_attack": abst_attack,
        "window_coverage": _ratio(len(classified_windows), wt),
        "window_coverage_den": f"{len(classified_windows)}/{wt}",
        "flagged_ambiguous_units": flagged_ambiguous, "flagged_mixed_units": flagged_mixed,
        "host": {
            "attacker_host_windows": len(attacker_hw_seen),
            "identified": h_ident, "unresolved": h_unres, "missed": h_missed, "abstained": h_abst,
            "false_identifications": h_false, "collateral_benign_host_windows": h_collat,
            "precision": _ratio(h_ident, h_ident + h_false), "precision_den": f"{h_ident}/{h_ident + h_false}",
            "recall": _ratio(h_ident, h_ident + h_unres + h_missed),
            "recall_den": f"{h_ident}/{h_ident + h_unres + h_missed}",
        },
    }
