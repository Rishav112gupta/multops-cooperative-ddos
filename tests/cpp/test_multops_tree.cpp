// Unit tests for MultopsTree. All time is driven by a ManualClock with the
// upstream epoch length (8 ms, 125 epochs/s), so results are deterministic.
//
// These are behavioural tests of the data structure. They are NOT
// experiments and say nothing about detection accuracy.

#include <algorithm>
#include <random>

#include "mini_test.hpp"
#include "multops/multops_tree.hpp"

using namespace multops;

namespace {

uint32_t ip(const char *text) {
    uint32_t a = 0;
    bool ok = parse_ipv4(text, a);
    if (!ok) throw std::runtime_error(std::string("bad ip ") + text);
    return a;
}

// Constant-rate source: `pps` packets per second for `epochs` epochs, spread
// evenly with a fractional accumulator. Advances the clock one epoch per step.
struct Flow {
    uint32_t addr;
    Direction dir;
    double pps;
    double acc = 0;
};

void run(MultopsTree &tree, ManualClock &clock, std::vector<Flow> flows, uint32_t epochs,
         uint32_t value = 1) {
    for (uint32_t e = 0; e < epochs; ++e) {
        for (auto &f : flows) {
            f.acc += f.pps / clock.epoch_frequency();
            while (f.acc >= 1.0) {
                tree.update(f.addr, f.dir, value);
                f.acc -= 1.0;
            }
        }
        clock.advance(1);
    }
}

const PrefixStats *find(const std::vector<PrefixStats> &v, uint32_t prefix, unsigned len) {
    for (auto &r : v)
        if (r.prefix == prefix && r.prefix_len == len) return &r;
    return nullptr;
}

MultopsConfig cfg(int64_t thresh, std::size_t memmax = 0) {
    MultopsConfig c;
    c.thresh = thresh;
    c.memmax_bytes = memmax;
    return c;
}

}  // namespace

// ---------------------------------------------------------------- basics

TEST(tree_empty_state) {
    ManualClock clock;
    MultopsTree t(cfg(100), clock);
    CHECK_EQ(t.table_count(), 1u);
    CHECK_EQ(t.counter_count(), 0u);
    CHECK_EQ(t.memory_bytes(), MultopsTree::table_bytes());
    CHECK(t.collect_stats(CollectMode::AllActive, false).empty());
    CHECK(t.lookup(ip("10.0.0.1")).empty());
    CHECK_EQ(t.check_invariants(), std::string());
}

TEST(tree_config_validation) {
    std::string err;
    MultopsConfig c = cfg(100);
    CHECK(MultopsTree::validate(c, &err));
    c.sample_ratio = 0.0;
    CHECK(!MultopsTree::validate(c, &err));
    c.sample_ratio = 1.5;
    CHECK(!MultopsTree::validate(c, &err));
    c.sample_ratio = 1.0;
    c.thresh = -1;
    CHECK(!MultopsTree::validate(c, &err));
}

TEST(tree_memmax_from_kb_applies_upstream_minimum) {
    CHECK_EQ(memmax_from_kb(0), 0u);
    CHECK_EQ(memmax_from_kb(1), 100u * 1024);
    CHECK_EQ(memmax_from_kb(99), 100u * 1024);
    CHECK_EQ(memmax_from_kb(600), 600u * 1024);
}

TEST(tree_single_packet_creates_only_level0_counter) {
    ManualClock clock;
    MultopsTree t(cfg(100), clock);
    UpdateResult r = t.update(ip("10.1.2.3"), Direction::Forward, 1);
    CHECK(r.counted);
    CHECK_EQ(r.prefix_len, 8);
    CHECK(!r.expanded);
    CHECK_EQ(t.counter_count(), 1u);
    auto path = t.lookup(ip("10.1.2.3"));
    REQUIRE(path.size() == 1);
    CHECK_EQ(path[0].prefix, ip("10.0.0.0"));
    CHECK_EQ(path[0].prefix_len, 8);
    CHECK_EQ(path[0].fwd_count, 1u);
    CHECK_EQ(path[0].rev_count, 0u);
    CHECK_EQ(t.check_invariants(), std::string());
}

TEST(tree_directions_are_tracked_separately) {
    ManualClock clock;
    MultopsTree t(cfg(1000000), clock);  // never expand
    run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 1000}}, 500);
    run(t, clock, {{ip("20.0.0.1"), Direction::Reverse, 1000}}, 500);
    auto a = t.lookup(ip("10.0.0.1"));
    auto b = t.lookup(ip("20.0.0.1"));
    REQUIRE(a.size() == 1 && b.size() == 1);
    CHECK(a[0].fwd_count == 500u * 8 && a[0].rev_count == 0u);
    CHECK(b[0].rev_count == 500u * 8 && b[0].fwd_count == 0u);
    CHECK_EQ(b[0].fwd_rate, 0);
    CHECK(b[0].rev_rate > 900);
}

// ---------------------------------------------------------------- rates

TEST(tree_rate_converges_to_offered_load) {
    ManualClock clock;
    MultopsTree t(cfg(1000000), clock);
    run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 10000}}, 1000);  // 8 s
    auto p = t.lookup(ip("10.0.0.1"));
    REQUIRE(!p.empty());
    CHECK_NEAR(p[0].fwd_rate, 10000, 10000 * 0.01);
    CHECK_EQ(p[0].rev_rate, 0);
}

TEST(tree_rate_decays_to_zero_when_idle) {
    ManualClock clock;
    MultopsTree t(cfg(1000000), clock);
    run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 10000}}, 500);
    clock.advance(200);  // > 100 idle epochs
    auto p = t.lookup(ip("10.0.0.1"));
    REQUIRE(!p.empty());
    CHECK_EQ(p[0].fwd_rate, 0);
}

// ---------------------------------------------------------------- expansion

TEST(tree_no_expansion_below_threshold) {
    ManualClock clock;
    MultopsTree t(cfg(100), clock);
    run(t, clock, {{ip("192.168.1.1"), Direction::Forward, 50}}, 1250);  // 10 s at 50 pps
    CHECK_EQ(t.table_count(), 1u);
    CHECK_EQ(t.lookup(ip("192.168.1.1")).size(), 1u);
}

TEST(tree_expands_one_level_per_update_and_cascades_to_host) {
    // Each update opens at most one level. Because the new child inherits
    // the parent's EWMA (already >= THRESH), the next packets keep expanding:
    // once the /8 crosses THRESH the path reaches /32 within 3 more packets.
    ManualClock clock;
    MultopsTree t(cfg(100), clock);
    const uint32_t a = ip("10.0.0.1");
    std::vector<std::size_t> depth_after_packet;
    for (int e = 0; e < 300; ++e) {
        for (int p = 0; p < 80; ++p) {  // 10 000 pps
            t.update(a, Direction::Forward, 1);
            std::size_t d = t.lookup(a).size();
            if (!depth_after_packet.empty())
                CHECK(d <= depth_after_packet.back() + 1);
            depth_after_packet.push_back(d);
        }
        clock.advance(1);
    }
    std::size_t first2 = std::find(depth_after_packet.begin(), depth_after_packet.end(), 2u) -
                         depth_after_packet.begin();
    std::size_t first4 = std::find(depth_after_packet.begin(), depth_after_packet.end(), 4u) -
                         depth_after_packet.begin();
    REQUIRE(first4 < depth_after_packet.size());
    CHECK_EQ(first4 - first2, 2u);
    auto path = t.lookup(a);
    REQUIRE(path.size() == 4);
    CHECK_EQ(path[3].prefix, ip("10.0.0.1"));
    CHECK_EQ(path[3].prefix_len, 32);
    CHECK(path[3].is_leaf);
    CHECK_EQ(t.table_count(), 4u);
    CHECK_EQ(t.check_invariants(), std::string());
}

TEST(tree_expansion_child_inherits_parent_ewma) {
    // Upstream make_counter(next_level, byte, &parent->fwd_and_rev_rate):
    // the new child starts with the parent's *whole* rate, even if other
    // children carried part of that traffic. Demonstrated here.
    ManualClock clock;
    MultopsTree t(cfg(100), clock);
    run(t, clock, {{ip("10.1.0.1"), Direction::Forward, 500},
                   {ip("10.2.0.1"), Direction::Forward, 500}}, 1);
    UpdateResult r;
    for (int i = 0; i < 1000 && !r.expanded; ++i) {
        clock.advance(1);
        r = t.update(ip("10.1.0.1"), Direction::Forward, 1);
    }
    REQUIRE(r.expanded);
    auto path = t.lookup(ip("10.1.0.1"));
    REQUIRE(path.size() == 2);
    // Just after expansion the /16 shows the /8's rate.
    CHECK_EQ(path[1].fwd_rate, path[0].fwd_rate);
}

TEST(tree_inherited_rate_inflates_low_rate_host_after_cascade) {
    // 200 hosts in 10.0.0.0/24 at 1 pps each (200 pps aggregate, THRESH 100).
    // Whichever host's packet triggers the cascade gets a /32 counter that
    // starts at the whole /8 rate and decays only over the following seconds.
    // Upstream behaviour; relevant to any per-prefix export (see report F4).
    ManualClock clock;
    MultopsTree t(cfg(100), clock);
    std::vector<Flow> hosts;
    for (uint32_t h = 1; h <= 200; ++h)
        hosts.push_back({ip("10.0.0.0") | h, Direction::Forward, 1.0});
    for (std::size_t i = 0; i < hosts.size(); ++i) hosts[i].acc = static_cast<double>(i) / 200.0;
    int64_t max_host_rate = 0;
    for (int e = 0; e < 125 * 20; ++e) {
        run(t, clock, hosts, 1);
        for (auto &r : t.collect_stats(CollectMode::LeavesOnly, false))
            if (r.prefix_len == 32) max_host_rate = std::max(max_host_rate, r.fwd_rate);
    }
    // True per-host rate is 1 pps; reported peak is two orders of magnitude higher.
    CHECK(max_host_rate >= 100);
}

TEST(tree_parent_rate_aggregates_children) {
    ManualClock clock;
    MultopsTree t(cfg(100), clock);
    run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 500},
                   {ip("10.0.0.2"), Direction::Forward, 500}}, 3000);  // 24 s
    auto a = t.lookup(ip("10.0.0.1"));
    auto b = t.lookup(ip("10.0.0.2"));
    REQUIRE(a.size() == 4 && b.size() == 4);
    CHECK_NEAR(a[0].fwd_rate, 1000, 15);   // /8
    CHECK_NEAR(a[2].fwd_rate, 1000, 15);   // /24
    CHECK_NEAR(a[3].fwd_rate, 500, 10);    // host
    CHECK_NEAR(b[3].fwd_rate, 500, 10);    // host
}

TEST(tree_expansion_on_reverse_rate) {
    ManualClock clock;
    MultopsTree t(cfg(100), clock);
    run(t, clock, {{ip("18.0.0.1"), Direction::Reverse, 10000}}, 1000);
    CHECK_EQ(t.lookup(ip("18.0.0.1")).size(), 4u);
}

// ---------------------------------------------------------------- folding

TEST(tree_fold_prunes_idle_subtrees) {
    ManualClock clock;
    MultopsTree t(cfg(100), clock);
    run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 10000}}, 1000);
    REQUIRE(t.table_count() == 4u);
    // Flood stops. Low-rate traffic elsewhere keeps update() (and fold) running.
    run(t, clock, {{ip("50.0.0.1"), Direction::Forward, 20}}, 125 * 30);
    CHECK_EQ(t.table_count(), 1u);
    CHECK(t.fold_runs() >= 30u);
    CHECK_EQ(t.check_invariants(), std::string());
}

TEST(tree_fold_units_upstream_vs_per_second) {
    // A /8 carrying 500 pps with THRESH = 1000 pps: below threshold per second,
    // but its scaled per-epoch average (500/125*1024 = 4096) is above 1000.
    for (int mode = 0; mode < 2; ++mode) {
        ManualClock clock;
        MultopsConfig c = cfg(1000);
        c.fold_units = mode == 0 ? FoldUnits::UpstreamScaledPerEpoch : FoldUnits::PerSecond;
        MultopsTree t(c, clock);
        run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 5000}}, 1000);  // expand
        REQUIRE(t.table_count() >= 2u);
        run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 500}}, 125 * 20);
        if (mode == 0)
            CHECK(t.table_count() >= 2u);  // upstream: subtree retained
        else
            CHECK_EQ(t.table_count(), 1u);  // per-second: subtree folded
    }
}

TEST(tree_fold_runs_per_instance) {
    // Upstream keeps prev_fold_time in a function-local static shared by all
    // IPRateMonitor instances. Here each instance keeps its own schedule.
    ManualClock c1, c2;
    MultopsTree a(cfg(100), c1), b(cfg(100), c2);
    run(a, c1, {{ip("10.0.0.1"), Direction::Forward, 50}}, 125 * 5);
    CHECK(a.fold_runs() >= 4u);
    CHECK_EQ(b.fold_runs(), 0u);
}

// ---------------------------------------------------------------- memory

TEST(tree_memory_accounting_matches_structure) {
    ManualClock clock;
    MultopsTree t(cfg(100), clock);
    run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 10000},
                   {ip("10.0.0.2"), Direction::Reverse, 10000}}, 1000);
    CHECK_EQ(t.memory_bytes(), t.table_count() * MultopsTree::table_bytes() +
                                   t.counter_count() * MultopsTree::counter_bytes());
    CHECK_EQ(t.check_invariants(), std::string());
}

TEST(tree_memmax_limits_expansion) {
    ManualClock clock;
    // Room for the root plus exactly one more table and three counters.
    std::size_t limit = 2 * MultopsTree::table_bytes() + 3 * MultopsTree::counter_bytes();
    MultopsTree t(cfg(100, limit), clock);
    for (int e = 0; e < 1500; ++e) {
        run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 10000},
                       {ip("20.0.0.1"), Direction::Forward, 10000}}, 1);
        REQUIRE(t.memory_bytes() <= limit);
    }
    CHECK_EQ(t.table_count(), 2u);
    CHECK_EQ(t.check_invariants(), std::string());
}

TEST(tree_memmax_blocks_new_counters_at_root) {
    ManualClock clock;
    std::size_t limit = MultopsTree::table_bytes() + 2 * MultopsTree::counter_bytes();
    MultopsTree t(cfg(1000000, limit), clock);
    CHECK(t.update(ip("1.0.0.1"), Direction::Forward, 1).counted);
    CHECK(t.update(ip("2.0.0.1"), Direction::Forward, 1).counted);
    CHECK(!t.update(ip("3.0.0.1"), Direction::Forward, 1).counted);  // no room
    CHECK_EQ(t.counter_count(), 2u);
}

TEST(tree_forced_fold_brings_memory_under_new_limit) {
    ManualClock clock;
    MultopsTree t(cfg(1), clock);  // THRESH 1: forced_fold step would be 0 upstream
    std::vector<Flow> flows;
    for (int i = 1; i <= 20; ++i)
        flows.push_back({static_cast<uint32_t>(i) << 24 | 1u, Direction::Forward, 2000});
    run(t, clock, flows, 600);
    REQUIRE(t.table_count() > 20u);
    std::size_t target = t.memory_bytes() / 3;
    t.set_memmax_bytes(target);  // must terminate (deviation D5 guard)
    CHECK(t.memory_bytes() <= target || t.table_count() == 1u);
    CHECK_EQ(t.check_invariants(), std::string());
}

TEST(tree_reset_clears_counters_and_memory) {
    ManualClock clock;
    MultopsTree t(cfg(100), clock);
    run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 10000}}, 1000);
    REQUIRE(t.table_count() == 4u);
    t.reset();
    CHECK_EQ(t.table_count(), 1u);
    CHECK_EQ(t.counter_count(), 0u);
    CHECK_EQ(t.memory_bytes(), MultopsTree::table_bytes());  // upstream leaks this accounting
    CHECK(t.collect_stats(CollectMode::AllActive, false).empty());
    CHECK_EQ(t.check_invariants(), std::string());
}

// ---------------------------------------------------------------- collection

TEST(tree_collect_all_levels_vs_leaves_only) {
    ManualClock clock;
    MultopsTree t(cfg(100), clock);
    run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 10000},
                   {ip("192.168.1.1"), Direction::Forward, 50}}, 1000);
    auto all = t.collect_stats(CollectMode::AllActive, false);
    auto leaves = t.collect_stats(CollectMode::LeavesOnly, false);
    CHECK_EQ(all.size(), 5u);        // 10/8, 10.0/16, 10.0.0/24, 10.0.0.1/32, 192/8
    CHECK_EQ(leaves.size(), 2u);     // 10.0.0.1/32, 192/8
    CHECK(find(all, ip("10.0.0.0"), 8) != nullptr);
    CHECK(find(all, ip("10.0.0.0"), 16) != nullptr);
    CHECK(find(all, ip("10.0.0.0"), 24) != nullptr);
    CHECK(find(leaves, ip("10.0.0.1"), 32) != nullptr);
    CHECK(find(leaves, ip("192.0.0.0"), 8) != nullptr);
    for (auto &r : all) {
        // prefixes are masked to their length
        uint32_t mask = r.prefix_len == 32 ? 0xFFFFFFFFu : ~(0xFFFFFFFFu >> r.prefix_len);
        CHECK_EQ(r.prefix & ~mask, 0u);
    }
}

TEST(tree_counts_are_exact_and_reset_per_window_rates_are_not) {
    ManualClock clock;
    MultopsTree t(cfg(1000000), clock);
    run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 1000}}, 125);  // 1 s
    auto w1 = t.collect_stats(CollectMode::AllActive, true);
    REQUIRE(w1.size() == 1);
    CHECK_EQ(w1[0].fwd_count, 1000u);           // exact
    CHECK(w1[0].fwd_rate < 1000);               // EWMA still ramping after 1 s
    auto w2 = t.collect_stats(CollectMode::AllActive, false);
    REQUIRE(w2.size() == 1);
    CHECK_EQ(w2[0].fwd_count, 0u);              // window reset
    CHECK(w2[0].fwd_rate > 0);                  // rate persists (decays)
}

TEST(tree_collect_skips_fully_idle_counters) {
    ManualClock clock;
    MultopsTree t(cfg(1000000), clock);
    run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 1000}}, 125);
    t.collect_stats(CollectMode::AllActive, true);  // clear counts
    clock.advance(500);                             // rate decays to 0
    CHECK(t.collect_stats(CollectMode::AllActive, true).empty());
    CHECK_EQ(t.counter_count(), 1u);                // counter still allocated
}

// ---------------------------------------------------------------- sampling

TEST(tree_sampling_ratio_scales_threshold_and_keeps_exact_counts) {
    ManualClock clock;
    MultopsConfig c = cfg(1000);
    c.sample_ratio = 0.5;
    c.rng_seed = 42;
    MultopsTree t(c, clock);
    CHECK_EQ(t.ratio_fixed16(), 0x8000u);
    CHECK_EQ(t.effective_thresh(), 500);
    run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 4000}}, 1250);  // 10 s
    auto p = t.lookup(ip("10.0.0.1"));
    REQUIRE(!p.empty());
    CHECK_NEAR(p[0].fwd_rate, 2000, 2000 * 0.1);  // rates are NOT rescaled (upstream)
}

TEST(tree_large_thresh_is_not_wrapped) {
    ManualClock clock;
    MultopsTree t(cfg(100000), clock);
    CHECK_EQ(t.effective_thresh(), 100000);
    // Upstream: (int)100000 * (unsigned)0x10000 wraps mod 2^32 before >> 16.
    uint32_t upstream = (static_cast<uint32_t>(100000) * 0x10000u) >> 16;
    CHECK_EQ(upstream, 34464u);
    MultopsTree huge(cfg(INT64_MAX), clock);
    CHECK_EQ(huge.effective_thresh(), INT64_MAX);
    MultopsConfig half = cfg(INT64_MAX);
    half.sample_ratio = 0.5;
    MultopsTree h(half, clock);
    CHECK_EQ(h.effective_thresh(), INT64_MAX / 2);
}

TEST(tree_sampling_is_reproducible_with_seed) {
    std::vector<int64_t> rates;
    for (int rep = 0; rep < 2; ++rep) {
        ManualClock clock;
        MultopsConfig c = cfg(1000000);
        c.sample_ratio = 0.3;
        c.rng_seed = 7;
        MultopsTree t(c, clock);
        run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 3000}}, 300);
        rates.push_back(t.lookup(ip("10.0.0.1"))[0].fwd_rate);
    }
    CHECK_EQ(rates[0], rates[1]);
}

// ---------------------------------------------------------------- bytes mode

TEST(tree_bytes_mode_high_rate_has_no_overflow) {
    // 100 000 pps * 1500 B = 150 MB/s. Upstream's 32-bit rate conversion
    // overflows above ~2.1 MB/s; this implementation widens to 64 bits.
    ManualClock clock;
    MultopsTree t(cfg(INT64_MAX), clock);
    run(t, clock, {{ip("10.0.0.1"), Direction::Forward, 100000}}, 1000, 1500);
    auto p = t.lookup(ip("10.0.0.1"));
    REQUIRE(!p.empty());
    CHECK_NEAR(p[0].fwd_rate, 150e6, 150e6 * 0.01);
}

// ---------------------------------------------------------------- robustness

TEST(tree_random_workload_preserves_invariants) {
    ManualClock clock;
    std::size_t limit = memmax_from_kb(200);
    MultopsTree t(cfg(50, limit), clock);
    std::mt19937 rng(12345);
    for (int step = 0; step < 200000; ++step) {
        uint32_t addr;
        if (rng() % 4 == 0)
            addr = static_cast<uint32_t>(rng());                             // scattered (spoof-like)
        else
            addr = (10u << 24) | static_cast<uint32_t>(rng() % 64);             // concentrated
        t.update(addr, (rng() & 1) ? Direction::Forward : Direction::Reverse, 1);
        if (rng() % 50 == 0) clock.advance(1 + static_cast<uint32_t>(rng() % 3));
        if (step % 20000 == 0) {
            REQUIRE(t.check_invariants().empty());
            REQUIRE(t.memory_bytes() <= limit);
        }
        if (step == 150000) t.set_memmax_bytes(memmax_from_kb(100));
    }
    CHECK_EQ(t.check_invariants(), std::string());
    CHECK(t.memory_bytes() <= memmax_from_kb(100));
}

// ---------------------------------------------------------------- paper context

TEST(tree_local_views_under_asymmetric_routing) {
    // Illustrates the paper's §3 problem at the data-structure level only.
    // Flow B (192.168.1.1 <-> 192.168.1.2): monitor A sees only requests
    // (forward, keyed by source 192.168.1.1); monitor B sees only the replies
    // (reverse, keyed by destination 192.168.1.1). Each local tree is
    // one-sided; their union is balanced. Flow A (10.0.0.1 flood) is one-sided
    // everywhere. No detection logic is exercised here.
    ManualClock clock;
    MultopsTree mon_a(cfg(100), clock), mon_b(cfg(100), clock);
    std::vector<Flow> at_a = {{ip("10.0.0.1"), Direction::Forward, 10000},
                              {ip("192.168.1.1"), Direction::Forward, 50}};
    std::vector<Flow> at_b = {{ip("192.168.1.1"), Direction::Reverse, 50}};
    for (int e = 0; e < 1250; ++e) {
        for (auto &f : at_a) {
            f.acc += f.pps / 125;
            while (f.acc >= 1) { mon_a.update(f.addr, f.dir, 1); f.acc -= 1; }
        }
        for (auto &f : at_b) {
            f.acc += f.pps / 125;
            while (f.acc >= 1) { mon_b.update(f.addr, f.dir, 1); f.acc -= 1; }
        }
        clock.advance(1);
    }
    auto a = mon_a.lookup(ip("192.168.1.1"));
    auto b = mon_b.lookup(ip("192.168.1.1"));
    REQUIRE(!a.empty() && !b.empty());
    CHECK(a[0].fwd_rate > 0 && a[0].rev_rate == 0);
    CHECK(b[0].rev_rate > 0 && b[0].fwd_rate == 0);
    CHECK_NEAR(a[0].fwd_rate, b[0].rev_rate, 2);
    auto flood = mon_a.lookup(ip("10.0.0.1"));
    REQUIRE(flood.size() == 4);
    CHECK(flood[3].fwd_rate > 9000 && flood[3].rev_rate == 0);
}

TEST(tree_ip_helpers) {
    uint32_t a;
    CHECK(parse_ipv4("192.168.1.2", a));
    CHECK_EQ(a, 0xC0A80102u);
    CHECK_EQ(ipv4_to_string(a), std::string("192.168.1.2"));
    CHECK(!parse_ipv4("256.0.0.1", a));
    CHECK(!parse_ipv4("1.2.3", a));
    CHECK(!parse_ipv4("1.2.3.4x", a));
    CHECK_EQ(prefix_to_string(0x0A000000u, 8), std::string("10.0.0.0/8"));
}

MINI_TEST_MAIN
