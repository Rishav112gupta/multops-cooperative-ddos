"""Detection engine (Phase 5).

Turns per-window global state from either Phase 4 aggregator into
classification decisions on NON-OVERLAPPING (prefix, window) units. It only
decides; it never sends mitigation commands (Phase 6). `would_mitigate`
lists the prefixes a mitigation step would act on.

Rules
-----
PAPER_LITERAL  [PAPER]  AINA 2026 Algorithm 2, lines 5-6, exactly as printed:
                   Ratio = R_in / R_out if R_out > 0 else infinity
                   malicious  iff  Ratio > tau_ratio  or  (R_out == 0 and R_in > tau_rate)
               Because Ratio is infinite whenever R_out == 0, the tau_rate
               clause can never change the outcome (Phase 1, P3): any unit with
               zero return traffic is flagged, whatever its volume -- even a
               unit with R_in == 0.
CORRECTED      [PROPOSAL]  minimum-volume gate first:
                   R_in < tau_min                 -> benign (below detection floor)
                   R_out == 0                     -> malicious (zero return)
                   R_in / R_out > tau_ratio       -> malicious
                   otherwise                      -> benign

All thresholds are EXPERIMENTAL values chosen by the caller. The paper gives
no numeric thresholds. R_in / R_out are in units per second: rates as
reported (paper aggregator) or exact window counts divided by the window
length (windowed aggregator).

Labels
------
malicious_host       flagged unit is a /32: detection AND attacker identification
malicious_ambiguous  flagged unit is coarser than /32: attack traffic detected,
                     but the prefix may also hold benign hosts; attribution is
                     unresolved and mitigating the whole prefix may hit them
benign               classified as not malicious
abstain              not classified (window incomplete: a required router report
                     is missing). Never counted as benign.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from aggregator.aggregator import (LEVELS, Key, NodeState, PaperWindow, ReconciledWindow, covers,
                                   mask)

PAPER_LITERAL = "paper_literal"
CORRECTED = "corrected"

MAL_HOST = "malicious_host"
MAL_AMBIGUOUS = "malicious_ambiguous"
BENIGN = "benign"
ABSTAIN = "abstain"


@dataclass(frozen=True)
class Thresholds:
    """Experimental detection thresholds (not from the paper)."""
    ratio: float              # tau_ratio
    min_rate: float = 0.0     # tau_rate  (paper rule's zero-return volume clause), units/s
    min_volume: float = 0.0   # tau_min   (corrected rule's volume gate), units/s


def classify(r_in: float, r_out: float, rule: str, th: Thresholds) -> Tuple[bool, str]:
    """Returns (malicious, reason) for one unit."""
    if rule == PAPER_LITERAL:
        ratio = r_in / r_out if r_out > 0 else math.inf
        if ratio > th.ratio:
            return True, "zero_return" if r_out == 0 else "ratio"
        if r_out == 0 and r_in > th.min_rate:        # unreachable: ratio is inf here
            return True, "zero_return_rate"
        return False, "ratio_ok"
    if rule == CORRECTED:
        if r_in < th.min_volume:
            return False, "below_min_volume"
        if r_out == 0:
            return True, "zero_return"
        if r_in / r_out > th.ratio:
            return True, "ratio"
        return False, "ratio_ok"
    raise ValueError(f"unknown rule {rule}")


@dataclass
class Decision:
    window: int
    prefix: str
    length: int
    r_in: float
    r_out: float
    label: str
    reason: str
    method: str

    @property
    def key(self) -> Key:
        return (self.prefix, self.length)

    @property
    def flagged(self) -> bool:
        return self.label in (MAL_HOST, MAL_AMBIGUOUS)


def _label(flagged: bool, length: int) -> str:
    if not flagged:
        return BENIGN
    return MAL_HOST if length == 32 else MAL_AMBIGUOUS


# ---------------------------------------------------------------- proposal side

def decision_nodes(window: ReconciledWindow) -> List[Tuple[Key, NodeState]]:
    """Non-overlapping partition of a reconciled window into exact nodes.

    Starting at each /8 (always exact), descend to the children only if no
    router reported a record at the node itself (then every child is exact and
    together the children hold all of the node's traffic). Otherwise the node
    is the finest exact unit for its traffic. Every record therefore falls in
    exactly one unit.
    """
    by_level: Dict[int, Dict[Key, NodeState]] = {L: {} for L in LEVELS}
    for k, n in window.nodes.items():
        by_level[k[1]][k] = n
    out: List[Tuple[Key, NodeState]] = []

    def visit(key: Key, node: NodeState) -> None:
        length = key[1]
        if length == 32:
            out.append((key, node))
            return
        nxt = LEVELS[LEVELS.index(length) + 1]
        children = [(k, n) for k, n in by_level[nxt].items() if covers(key, k)]
        child_f = sum(n.fwd for _, n in children)
        child_r = sum(n.rev for _, n in children)
        if children and all(n.exact for _, n in children) and (child_f, child_r) == (node.fwd, node.rev):
            for k, n in sorted(children):
                visit(k, n)
        else:
            out.append((key, node))

    for k, n in sorted(by_level[8].items()):
        visit(k, n)
    return out


class CorrectedDetector:
    """Decisions on WindowedAggregator output. Abstains on incomplete windows.

    aggregate_low_volume (opt-in, [PROPOSAL] variant): units that fall below
    tau_min individually are re-examined as groups under their exact common
    ancestor (/24, then /16, then /8). If a group's summed traffic passes the
    rule, every member that is itself one-sided or above tau_ratio is flagged
    (reason "aggregate:<prefix>"). Members with adequate return traffic are
    never flagged this way. Targets distributed low-rate attacks; it can also
    flag many low-rate benign one-way senders that share a prefix.
    """

    def __init__(self, rule: str, th: Thresholds, window_s: float, method: str = "proposal",
                 aggregate_low_volume: bool = False):
        self.rule, self.th, self.window_s, self.method = rule, th, window_s, method
        self.aggregate_low_volume = aggregate_low_volume

    def decide(self, window: ReconciledWindow) -> List[Decision]:
        out = []
        for (p, length), n in decision_nodes(window):
            r_in, r_out = n.fwd / self.window_s, n.rev / self.window_s
            if not window.complete:
                missing = ",".join(str(r) for r in sorted(window.missing_routers))
                out.append(Decision(window.index, p, length, r_in, r_out, ABSTAIN,
                                    f"missing_router:{missing}", self.method))
                continue
            flagged, reason = classify(r_in, r_out, self.rule, self.th)
            out.append(Decision(window.index, p, length, r_in, r_out, _label(flagged, length),
                                reason, self.method))
        if self.aggregate_low_volume and window.complete:
            self._aggregate(out)
        return out

    def _aggregate(self, decisions: List[Decision]) -> None:
        done = set()
        for anc_len in (24, 16, 8):
            groups: Dict[str, List[Decision]] = {}
            for d in decisions:
                if d.length > anc_len and d.reason == "below_min_volume" and id(d) not in done:
                    groups.setdefault(mask(d.prefix, anc_len), []).append(d)
            for anc, members in groups.items():
                if len(members) < 2:
                    continue
                g_in = sum(d.r_in for d in members)
                g_out = sum(d.r_out for d in members)
                if g_in < self.th.min_volume or not (g_out == 0 or g_in / g_out > self.th.ratio):
                    continue
                for d in members:
                    done.add(id(d))
                    if d.r_out == 0 or d.r_in / d.r_out > self.th.ratio:
                        d.label = _label(True, d.length)
                        d.reason = f"aggregate:{anc}/{anc_len}"


# ---------------------------------------------------------------- paper side

class PaperDetector:
    """Algorithm 2 decisions on PaperAggregator output.

    The paper flags every key independently (overlapping keys). To score
    without double counting, units are the most specific keys in the fused map
    (keys with no descendant key); a unit counts as flagged if its own key or
    any ancestor key is flagged, because blocking the ancestor would cover it.
    `flagged_keys(window)` returns the paper's raw per-key flags.
    """

    def __init__(self, rule: str, th: Thresholds, method: str = "paper"):
        self.rule, self.th, self.method = rule, th, method

    def flagged_keys(self, window: PaperWindow) -> Dict[Key, str]:
        res = {}
        for k, (r_in, r_out) in window.state.items():
            flagged, reason = classify(r_in, r_out, self.rule, self.th)
            if flagged:
                res[k] = reason
        return res

    def decide(self, window: PaperWindow) -> List[Decision]:
        flags = self.flagged_keys(window)
        keys = list(window.state)
        out = []
        for k in sorted(keys):
            if any(o != k and covers(k, o) for o in keys):
                continue                                  # not most specific
            r_in, r_out = window.state[k]
            hit = [a for a in flags if covers(a, k)]
            if hit:
                own = flags.get(k)
                reason = own if own else f"ancestor_flagged:{min(hit, key=lambda a: a[1])[0]}/" \
                                         f"{min(hit, key=lambda a: a[1])[1]}"
                out.append(Decision(window.index, k[0], k[1], r_in, r_out, _label(True, k[1]),
                                    reason, self.method))
            else:
                out.append(Decision(window.index, k[0], k[1], r_in, r_out, BENIGN, "ratio_ok",
                                    self.method))
        return out


def would_mitigate(decisions: List[Decision]) -> List[Key]:
    """Prefixes a mitigation step WOULD act on (no command is sent in Phase 5)."""
    return sorted({d.key for d in decisions if d.flagged})
