/*
 * coopipratemonitor.{cc,hh} -- MULTOPS rate monitor with periodic export.
 *
 * Packet path, configuration keywords and handlers mirror Click's
 * IPRateMonitor (elements/ip/ipratemon.{cc,hh}); the data structure lives in
 * the Click-independent multops core library (multops/).
 */

#include <click/config.h>
#include "coopipratemonitor.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <click/packet_anno.hh>
#include <clicknet/ip.h>
#include <limits.h>
CLICK_DECLS

namespace {
enum { h_look, h_snapshot, h_stats, h_thresh, h_mem, h_memmax, h_exports,
       h_reset, h_memmax_w, h_export_now };
const uint16_t kDefaultAggregatorPort = 49555;   // paper Sec. 5.1

int32_t clamp_anno(int64_t v) {
    return v > INT_MAX ? INT_MAX : static_cast<int32_t>(v);
}
}

CoopIPRateMonitor::CoopIPRateMonitor()
    : _tree(0), _count_packets(true), _anno(true),
      _export_mode(multops::CollectMode::AllActive), _interval_msec(0),
      _timer(this), _have_aggregator(false), _aggregator_port(kDefaultAggregatorPort),
      _reset_epoch(0), _exports(0)
{
}

CoopIPRateMonitor::~CoopIPRateMonitor()
{
}

int
CoopIPRateMonitor::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String type, aggregator, export_mode = "ALL", fold_units = "UPSTREAM";
    uint32_t ratio_fixed = 0x10000;
    int64_t thresh = 0;
    uint32_t memory_kb = 0;
    uint64_t seed = 1;
    _anno = true;
    _interval_msec = 0;

    if (Args(conf, this, errh)
        .read_mp("TYPE", WordArg(), type)
        .read_mp("RATIO", FixedPointArg(16), ratio_fixed)
        .read_mp("THRESH", thresh)
        .read_p("MEMORY", memory_kb)
        .read_p("ANNO", _anno)
        .read("INTERVAL", SecondsArg(3), _interval_msec)
        .read("AGGREGATOR", AnyArg(), aggregator)
        .read("EXPORT", WordArg(), export_mode)
        .read("FOLD_UNITS", WordArg(), fold_units)
        .read("SEED", seed)
        .complete() < 0)
        return -1;

    if (type.upper() == "PACKETS")
        _count_packets = true;
    else if (type.upper() == "BYTES")
        _count_packets = false;
    else
        return errh->error("TYPE should be PACKETS or BYTES");

    if (ratio_fixed == 0 || ratio_fixed > 0x10000)
        return errh->error("RATIO must be in (0, 1]");

    if (export_mode.upper() == "ALL")
        _export_mode = multops::CollectMode::AllActive;
    else if (export_mode.upper() == "LEAVES")
        _export_mode = multops::CollectMode::LeavesOnly;
    else
        return errh->error("EXPORT should be ALL or LEAVES");

    _config = multops::MultopsConfig();
    if (fold_units.upper() == "UPSTREAM")
        _config.fold_units = multops::FoldUnits::UpstreamScaledPerEpoch;
    else if (fold_units.upper() == "PERSEC")
        _config.fold_units = multops::FoldUnits::PerSecond;
    else
        return errh->error("FOLD_UNITS should be UPSTREAM or PERSEC");

    _config.thresh = thresh;
    _config.sample_ratio = ratio_fixed / 65536.0;
    _config.memmax_bytes = multops::memmax_from_kb(memory_kb);
    _config.rng_seed = seed;
    std::string err;
    if (!multops::MultopsTree::validate(_config, &err))
        return errh->error("%s", err.c_str());

    _have_aggregator = false;
    if (aggregator) {
        String addr_part = aggregator, port_part;
        int colon = aggregator.find_left(':');
        if (colon >= 0) {
            addr_part = aggregator.substring(0, colon);
            port_part = aggregator.substring(colon + 1);
        }
        if (!IPAddressArg().parse(addr_part, _aggregator_addr, this))
            return errh->error("AGGREGATOR: bad address %<%s%>", addr_part.c_str());
        _aggregator_port = kDefaultAggregatorPort;
        if (port_part && !IntArg().parse(port_part, _aggregator_port))
            return errh->error("AGGREGATOR: bad port %<%s%>", port_part.c_str());
        _have_aggregator = true;
    }
    return 0;
}

int
CoopIPRateMonitor::initialize(ErrorHandler *)
{
    _tree = new multops::MultopsTree(_config, _clock);
    _reset_epoch = _clock.now_epoch();
    _timer.initialize(this);
    if (_interval_msec)
        _timer.schedule_after_msec(_interval_msec);
    if (_have_aggregator)
        click_chatter("%s: AGGREGATOR %s:%u configured; UDP export is not implemented "
                      "until Phase 3 (snapshots are kept in the 'snapshot' handler)",
                      declaration().c_str(), _aggregator_addr.unparse().c_str(),
                      _aggregator_port);
    return 0;
}

void
CoopIPRateMonitor::cleanup(CleanupStage)
{
    delete _tree;
    _tree = 0;
}

// For forward packets (port 0) account the source address; for reverse
// packets (port 1) the destination address -- identical to upstream.
inline void
CoopIPRateMonitor::update_rates(Packet *p, bool forward)
{
    const click_ip *ip = p->ip_header();
    uint32_t value = _count_packets ? 1 : ntohs(ip->ip_len);
    uint32_t addr = ntohl(forward ? ip->ip_src.s_addr : ip->ip_dst.s_addr);
    multops::UpdateResult r = _tree->update(
        addr, forward ? multops::Direction::Forward : multops::Direction::Reverse, value);
    if (_anno && r.prefix_len) {
        SET_FWD_RATE_ANNO(p, clamp_anno(r.fwd_rate));
        SET_REV_RATE_ANNO(p, clamp_anno(r.rev_rate));
    }
}

void
CoopIPRateMonitor::push(int port, Packet *p)
{
    _lock.acquire();
    update_rates(p, port == 0);
    _lock.release();
    output(port).push(p);
}

Packet *
CoopIPRateMonitor::pull(int port)
{
    Packet *p = input(port).pull();
    if (p) {
        _lock.acquire();
        update_rates(p, port == 0);
        _lock.release();
    }
    return p;
}

// Paper Sec. 4.2: collect_stats_recursive() + send_stats_packet(). In Phase 2
// the collected records are kept as a snapshot; Phase 3 adds the sender.
void
CoopIPRateMonitor::do_export()
{
    _lock.acquire();
    _snapshot = _tree->collect_stats(_export_mode, true);
    _snapshot_time = Timestamp::now();
    ++_exports;
    _lock.release();
}

void
CoopIPRateMonitor::run_timer(Timer *)
{
    do_export();
    _timer.reschedule_after_msec(_interval_msec);
}

String
CoopIPRateMonitor::read_handler(Element *e, void *thunk)
{
    CoopIPRateMonitor *m = static_cast<CoopIPRateMonitor *>(e);
    StringAccum sa;
    m->_lock.acquire();
    switch ((intptr_t) thunk) {
    case h_look:
        // Upstream prints epochs (not jiffies, despite its docs) since reset.
        sa << (m->_clock.now_epoch() - m->_reset_epoch) << '\n' << m->_tree->look().c_str();
        break;
    case h_snapshot:
        sa << "# export " << m->_exports << " at " << m->_snapshot_time << '\n';
        sa << "prefix,leaf,fwd_rate,rev_rate,fwd_count,rev_count\n";
        for (size_t i = 0; i < m->_snapshot.size(); ++i) {
            const multops::PrefixStats &r = m->_snapshot[i];
            sa << multops::prefix_to_string(r.prefix, r.prefix_len).c_str() << ','
               << (r.is_leaf ? 1 : 0) << ',' << r.fwd_rate << ',' << r.rev_rate << ','
               << r.fwd_count << ',' << r.rev_count << '\n';
        }
        break;
    case h_stats:
        sa << "tables " << m->_tree->table_count() << '\n'
           << "counters " << m->_tree->counter_count() << '\n'
           << "memory_bytes " << m->_tree->memory_bytes() << '\n'
           << "memmax_bytes " << m->_tree->memmax_bytes() << '\n'
           << "fold_runs " << m->_tree->fold_runs() << '\n'
           << "exports " << m->_exports << '\n'
           << "invariants " << (m->_tree->check_invariants().empty() ? "ok" : "BROKEN") << '\n';
        break;
    case h_thresh: sa << m->_tree->effective_thresh(); break;
    case h_mem: sa << m->_tree->memory_bytes(); break;
    case h_memmax: sa << m->_tree->memmax_bytes(); break;
    case h_exports: sa << m->_exports; break;
    }
    m->_lock.release();
    return sa.take_string();
}

int
CoopIPRateMonitor::lookup_handler(int, String &str, Element *e, const Handler *,
                                  ErrorHandler *errh)
{
    CoopIPRateMonitor *m = static_cast<CoopIPRateMonitor *>(e);
    IPAddress a;
    if (!IPAddressArg().parse(cp_uncomment(str), a, e))
        return errh->error("expected IP address");
    StringAccum sa;
    m->_lock.acquire();
    std::vector<multops::PrefixStats> path = m->_tree->lookup(ntohl(a.addr()));
    m->_lock.release();
    for (size_t i = 0; i < path.size(); ++i)
        sa << multops::prefix_to_string(path[i].prefix, path[i].prefix_len).c_str() << '\t'
           << path[i].fwd_rate << '\t' << path[i].rev_rate << '\t'
           << path[i].fwd_count << '\t' << path[i].rev_count << '\n';
    str = sa.take_string();
    return 0;
}

int
CoopIPRateMonitor::write_handler(const String &str, Element *e, void *thunk,
                                 ErrorHandler *errh)
{
    CoopIPRateMonitor *m = static_cast<CoopIPRateMonitor *>(e);
    switch ((intptr_t) thunk) {
    case h_reset:
        m->_lock.acquire();
        m->_tree->reset();
        m->_reset_epoch = m->_clock.now_epoch();
        m->_lock.release();
        return 0;
    case h_memmax_w: {
        uint32_t kb;
        if (!IntArg().parse(cp_uncomment(str), kb))
            return errh->error("expected memory limit in KB");
        m->_lock.acquire();
        m->_tree->set_memmax_bytes(multops::memmax_from_kb(kb));
        m->_lock.release();
        return 0;
    }
    case h_export_now:
        m->do_export();
        return 0;
    }
    return -1;
}

void
CoopIPRateMonitor::add_handlers()
{
    add_read_handler("look", read_handler, h_look);
    add_read_handler("snapshot", read_handler, h_snapshot);
    add_read_handler("stats", read_handler, h_stats);
    add_read_handler("thresh", read_handler, h_thresh);
    add_read_handler("mem", read_handler, h_mem);
    add_read_handler("memmax", read_handler, h_memmax);
    add_read_handler("exports", read_handler, h_exports);
    add_write_handler("reset", write_handler, h_reset, Handler::BUTTON);
    add_write_handler("memmax", write_handler, h_memmax_w);
    add_write_handler("export", write_handler, h_export_now, Handler::BUTTON);
    set_handler("lookup", Handler::f_read | Handler::f_read_param, lookup_handler);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(userlevel MultopsCore)
EXPORT_ELEMENT(CoopIPRateMonitor)
