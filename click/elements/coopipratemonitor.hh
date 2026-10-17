#ifndef CLICK_COOPIPRATEMONITOR_HH
#define CLICK_COOPIPRATEMONITOR_HH
#include <click/element.hh>
#include <click/timer.hh>
#include <click/ipaddress.hh>
#include <click/sync.hh>
#include <vector>
#include "multops/multops_tree.hpp"
CLICK_DECLS

/*
=c

CoopIPRateMonitor(TYPE, RATIO, THRESH [, MEMORY, ANNO, I<keywords>])

=s ipmeasure

MULTOPS rate monitor with periodic statistics export (cooperative MULTOPS)

=d

Re-implementation of Click's IPRateMonitor (Gil/Chen/Kohler) built on the
standalone multops core library, extended with the periodic export described
in "Decoupled State Aggregation for Asymmetric DDoS Detection using MULTOPS"
(AINA 2026, Sec. 4.2). Rate tracking, expansion, folding and the memory
limit follow upstream; see docs/PHASE2_MULTOPS_VERIFICATION.md for every
deviation.

Packets arriving on input 0 are accounted to their SOURCE address as
forward traffic; packets arriving on input 1 are accounted to their
DESTINATION address as reverse traffic. Packets leave on the output with the
same number.

Positional arguments are as for IPRateMonitor:

=over 8

=item TYPE

PACKETS or BYTES.

=item RATIO

Fraction (0 < RATIO <= 1) of packets that update the rate estimators.
Window counts are always exact.

=item THRESH

Expansion threshold in units per second, specified as if RATIO were 1.

=item MEMORY

Memory limit in kilobytes. Minimum 100; 0 means unlimited. Default 0.

=item ANNO

Boolean. If true, set FWD_RATE_ANNO and REV_RATE_ANNO on each packet.
Default true.

=back

Keywords (new):

=over 8

=item INTERVAL

Export period, in seconds (millisecond precision). 0 disables the export timer.
Default 0.

=item AGGREGATOR

Aggregator address, "ADDR" or "ADDR:PORT" (default port 49555). Parsed and
stored in Phase 2; the UDP sender is implemented in Phase 3.

=item EXPORT

ALL (every active counter at every prefix length, the default) or LEAVES
(only deepest counters).

=item FOLD_UNITS

UPSTREAM (default; compare per-epoch scaled averages with THRESH exactly as
upstream does) or PERSEC (compare per-second rates with THRESH).

=item SEED

Seed for the sampling and fold-direction random generator. Default 1.

=back

=h look read-only

Rates (per second) of every active prefix, as upstream. First line: epochs
(8 ms each) since the last reset, as upstream actually prints.

=h snapshot read-only

CSV of the most recent export: prefix/len,leaf,fwd_rate,rev_rate,fwd_count,rev_count.

=h lookup read-only (with parameter)

Per-level rates for an address: "lookup ADDR".

=h stats read-only

Tables, counters, memory bytes, fold runs, exports.

=h thresh, mem, memmax, exports read-only

=h memmax write-only

New memory limit in KB (forces a fold if needed).

=h reset write-only

Clear all counters.

=h export write-only

Run one export immediately (same as a timer expiry).

=e

  CoopIPRateMonitor(PACKETS, 1, 1000, 600, INTERVAL 1, AGGREGATOR 127.0.0.1:49555);

=a IPRateMonitor */

class CoopIPRateMonitor : public Element { public:

    CoopIPRateMonitor() CLICK_COLD;
    ~CoopIPRateMonitor() CLICK_COLD;

    const char *class_name() const override { return "CoopIPRateMonitor"; }
    const char *port_count() const override { return "1-2/1-2"; }

    int configure(Vector<String> &conf, ErrorHandler *errh) override CLICK_COLD;
    int initialize(ErrorHandler *errh) override CLICK_COLD;
    void cleanup(CleanupStage stage) override CLICK_COLD;
    void add_handlers() override CLICK_COLD;

    void push(int port, Packet *p) override;
    Packet *pull(int port) override;
    void run_timer(Timer *t) override;

  private:

    // multops::Clock backed by click_jiffies(), with upstream's epoch length.
    class JiffiesClock : public multops::Clock { public:
        uint32_t now_epoch() const override { return click_jiffies() >> 3; }
        uint32_t epoch_frequency() const override { return CLICK_HZ >> 3; }
    };

    JiffiesClock _clock;
    multops::MultopsConfig _config;
    multops::MultopsTree *_tree;
    Spinlock _lock;

    bool _count_packets;
    bool _anno;
    multops::CollectMode _export_mode;
    uint32_t _interval_msec;
    Timer _timer;
    bool _have_aggregator;
    IPAddress _aggregator_addr;
    uint16_t _aggregator_port;
    uint32_t _reset_epoch;

    std::vector<multops::PrefixStats> _snapshot;
    Timestamp _snapshot_time;
    uint64_t _exports;

    void update_rates(Packet *p, bool forward);
    void do_export();

    static String read_handler(Element *e, void *thunk) CLICK_COLD;
    static int lookup_handler(int op, String &str, Element *e, const Handler *h,
                              ErrorHandler *errh) CLICK_COLD;
    static int write_handler(const String &str, Element *e, void *thunk,
                             ErrorHandler *errh) CLICK_COLD;
};

CLICK_ENDDECLS
#endif
