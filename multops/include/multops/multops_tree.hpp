// multops_tree.hpp -- MULTOPS (Multi-Level Tree for Online Packet Statistics).
//
// A Click-independent re-implementation of the data structure inside Click's
// IPRateMonitor element (elements/ip/ipratemon.{hh,cc}, Gil/Chen/Kohler),
// which the AINA 2026 paper states it extended. Behaviour follows upstream
// unless a deviation is listed in docs/PHASE2_MULTOPS_VERIFICATION.md.
//
// Structure
//   * 4 levels, 256-ary. Level L (0..3) is keyed by byte L of the IPv4
//     address, so a counter at level L describes a /(8*(L+1)) prefix.
//   * A Stats table holds 256 optional Counter slots. A Counter holds a pair
//     of EWMA rates (forward, reverse), per-window exact counts, and an
//     optional pointer to the next-level Stats table.
//   * Each update walks from the root to the deepest existing counter on the
//     address's path and updates *every* counter on that path, so a parent's
//     rate is the aggregate of its subtree.
//   * When the deepest counter's forward or reverse rate (per second)
//     reaches `thresh`, one more level is opened beneath it (expansion). The
//     new child counter inherits the parent's EWMA state (upstream
//     behaviour).
//   * About once per second the tree is folded: subtrees whose parent rates
//     have fallen below the threshold are deleted, oldest-or-newest first.
//
// Direction convention (upstream IPRateMonitor)
//   Forward: packet arrived on input 0 and is keyed by its SOURCE address.
//            -> "traffic coming FROM this prefix"
//   Reverse: packet arrived on input 1 and is keyed by its DESTINATION address.
//            -> "traffic going TO this prefix"
//
// Not thread-safe: callers serialize access (the Click element uses a
// Spinlock exactly like upstream).

#ifndef MULTOPS_MULTOPS_TREE_HPP
#define MULTOPS_MULTOPS_TREE_HPP

#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "multops/clock.hpp"
#include "multops/rate_ewma.hpp"

namespace multops {

enum class Direction : unsigned { Forward = 0, Reverse = 1 };

// How fold() compares a subtree's parent rate against the fold threshold.
enum class FoldUnits {
    // Upstream: compares scaled_average() (samples per EPOCH, x1024) with the
    // per-SECOND threshold. With 125 epochs/s this folds only once the rate
    // drops below ~thresh * 125/1024 ~= 0.12 * thresh. Default, for fidelity.
    UpstreamScaledPerEpoch,
    // Alternative: compare the per-second rate with the threshold (the units
    // the threshold is documented in). Provided for sensitivity experiments.
    PerSecond,
};

enum class CollectMode {
    AllActive,   // every counter with activity, at every level (/8 ... /32)
    LeavesOnly,  // only counters with no expanded child (deepest view)
};

struct MultopsConfig {
    // THRESH: expansion threshold in units/second, given "as if RATIO were 1"
    // (upstream semantics). Must be >= 0.
    int64_t thresh = 1;
    // RATIO: probability that a packet updates the EWMAs (0 < ratio <= 1).
    // Stored as 16-bit fixed point like upstream (FixedPointArg(16)).
    double sample_ratio = 1.0;
    // MEMORY limit in bytes; 0 = unlimited. Use memmax_from_kb() to apply the
    // upstream 100 KB minimum.
    std::size_t memmax_bytes = 0;
    FoldUnits fold_units = FoldUnits::UpstreamScaledPerEpoch;
    // Seed for the sampling and fold-direction RNG (upstream uses
    // click_random(); a seed makes runs reproducible).
    uint64_t rng_seed = 1;
};

// Upstream MEMORY handling: KB, minimum 100 KB, 0 means unlimited.
std::size_t memmax_from_kb(std::size_t kb);

// One exported prefix record (the paper's collect_stats_recursive output).
struct PrefixStats {
    uint32_t prefix = 0;       // host byte order, low bits zeroed
    uint8_t prefix_len = 0;    // 8, 16, 24 or 32
    bool is_leaf = false;      // no expanded child below this counter
    int64_t fwd_rate = 0;      // EWMA, units/second (truncated, upstream conversion)
    int64_t rev_rate = 0;
    uint64_t fwd_count = 0;    // exact units counted in the current window
    uint64_t rev_count = 0;
};

// Result of a single update (what upstream writes into packet annotations).
struct UpdateResult {
    bool counted = false;      // false if a memory limit stopped the update at the root
    uint8_t prefix_len = 0;    // depth of the deepest counter reached
    int64_t fwd_rate = 0;      // rates of that counter, units/second
    int64_t rev_rate = 0;
    bool expanded = false;     // a new level was opened by this update
};

class MultopsTree {
  public:
    // Returns false (and a message) if the config is out of range. The
    // constructor clamps instead of failing, so call this first.
    static bool validate(const MultopsConfig &config, std::string *error);

    MultopsTree(const MultopsConfig &config, const Clock &clock);
    ~MultopsTree();
    MultopsTree(const MultopsTree &) = delete;
    MultopsTree &operator=(const MultopsTree &) = delete;

    // Account `value` units (1 for PACKETS, IP length for BYTES) for address
    // `addr_host` (host byte order) in direction `dir`.
    UpdateResult update(uint32_t addr_host, Direction dir, uint32_t value);

    // Upstream fold(thresh): prune subtrees whose parent rates are below
    // `thresh`. Normally invoked automatically about once per second.
    void fold(int64_t thresh);
    // Upstream forced_fold(): fold with increasing thresholds until under
    // the memory limit.
    void forced_fold();
    // Upstream "memmax" write handler.
    void set_memmax_bytes(std::size_t bytes);
    // Upstream "reset" write handler: drop all counters, keep the root table.
    void reset();

    // The paper's collect_stats_recursive(): walk the tree and return the
    // active prefixes. If reset_window_counts is true, the exact per-window
    // counters are zeroed afterwards (EWMA rates are never reset; they decay).
    std::vector<PrefixStats> collect_stats(CollectMode mode, bool reset_window_counts);

    // Per-level view for one address, root first (upstream llrpc
    // CLICK_LLRPC_IPRATEMON_FWD_N_REV_AVG). The paper's Lookup(T_local, ip).
    std::vector<PrefixStats> lookup(uint32_t addr_host);

    // Text dump in the format of upstream's "look" handler body.
    std::string look();

    // Introspection.
    std::size_t memory_bytes() const { return alloced_mem_; }
    std::size_t memmax_bytes() const { return memmax_; }
    std::size_t table_count() const { return table_count_; }
    std::size_t counter_count() const { return counter_count_; }
    int64_t effective_thresh() const { return thresh_; }
    uint32_t ratio_fixed16() const { return ratio_; }
    uint64_t fold_runs() const { return fold_runs_; }
    // Consistency check of the age list, parent links and memory accounting.
    // Returns an empty string if consistent, else a description of the problem.
    std::string check_invariants() const;

    // Sizes used for memory accounting (exposed for tests and docs).
    static std::size_t counter_bytes();
    static std::size_t table_bytes();

  private:
    struct Stats;
    struct Counter {
        explicit Counter(uint32_t now) : rates(now), next_level(nullptr) {
            window_count[0] = window_count[1] = 0;
        }
        Counter(const RateEWMA2 &inherited) : rates(inherited), next_level(nullptr) {
            window_count[0] = window_count[1] = 0;
        }
        RateEWMA2 rates;
        Stats *next_level;
        uint64_t window_count[2];
    };
    struct Stats {
        enum { kMaxCounters = 256 };
        Stats() : parent(nullptr), prev(nullptr), next(nullptr) {
            for (int i = 0; i < kMaxCounters; ++i) counter[i] = nullptr;
        }
        Counter *parent;           // nullptr for the root table
        Stats *prev, *next;        // age list (oldest first)
        Counter *counter[kMaxCounters];
    };

    Counter *make_counter(Stats *s, unsigned char index, const RateEWMA2 *inherit);
    Stats *new_table();
    // Deletes `s` and its whole subtree, unlinking each table from the age
    // list. Returns s's neighbour (next if forward, else prev) after removal.
    Stats *destroy_table(Stats *s, bool forward);
    void destroy_counter(Counter *c);
    bool below_fold_threshold(const Counter *c, int64_t thresh) const;
    void collect(Stats *s, uint32_t prefix, unsigned level, CollectMode mode,
                 bool reset_counts, std::vector<PrefixStats> &out);
    void look(Stats *s, const std::string &ip, std::string &out);
    PrefixStats make_record(Counter *c, uint32_t prefix, unsigned level);
    bool sample();

    const Clock &clock_;
    int64_t thresh_;       // effective threshold (thresh * ratio >> 16)
    uint32_t ratio_;       // 16-bit fixed point, 0x10000 == 1.0
    std::size_t memmax_;
    FoldUnits fold_units_;
    std::mt19937_64 rng_;

    Stats *base_;
    Stats *first_, *last_;
    std::size_t alloced_mem_;
    std::size_t table_count_;
    std::size_t counter_count_;
    uint32_t prev_fold_epoch_;  // per instance (upstream: function-static, shared)
    uint64_t fold_runs_;
};

// Formatting helpers.
std::string ipv4_to_string(uint32_t addr_host);
bool parse_ipv4(const std::string &text, uint32_t &addr_host);
std::string prefix_to_string(uint32_t prefix_host, unsigned len);

}  // namespace multops

#endif
