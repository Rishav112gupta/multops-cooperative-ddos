// multops_tree.cpp -- see multops_tree.hpp for the design overview.
//
// Function-by-function correspondence with upstream Click
// (elements/ip/ipratemon.{hh,cc}):
//   MultopsTree::update        <- IPRateMonitor::update (+ push sampling)
//   MultopsTree::make_counter  <- IPRateMonitor::make_counter
//   MultopsTree::fold          <- IPRateMonitor::fold
//   MultopsTree::forced_fold   <- IPRateMonitor::forced_fold
//   MultopsTree::destroy_table <- IPRateMonitor::Stats::~Stats
//   MultopsTree::reset         <- IPRateMonitor::reset_write_handler
//   MultopsTree::look          <- IPRateMonitor::print
//   MultopsTree::lookup        <- llrpc CLICK_LLRPC_IPRATEMON_FWD_N_REV_AVG
//   MultopsTree::collect_stats <- (new) paper §4.2 collect_stats_recursive

#include "multops/multops_tree.hpp"

#include <cstdio>
#include <set>
#include <sstream>

namespace multops {

namespace {
// Upstream constants (ipratemon.{hh,cc}).
const unsigned kMemmaxMinKb = 100;          // MEMMAX_MIN
const float kFoldFactor = 0.9f;             // FOLD_FACTOR
const float kFoldIncreaseFactor = 5.0f;     // FOLD_INCREASE_FACTOR
}  // namespace

std::size_t memmax_from_kb(std::size_t kb) {
    if (kb && kb < kMemmaxMinKb)
        kb = kMemmaxMinKb;
    return kb * 1024;
}

std::size_t MultopsTree::counter_bytes() { return sizeof(Counter); }
std::size_t MultopsTree::table_bytes() { return sizeof(Stats); }

bool MultopsTree::validate(const MultopsConfig &config, std::string *error) {
    if (!(config.sample_ratio > 0.0) || config.sample_ratio > 1.0) {
        if (error) *error = "ratio must be in (0, 1]";
        return false;
    }
    if (config.thresh < 0) {
        if (error) *error = "thresh must be >= 0";
        return false;
    }
    return true;
}

MultopsTree::MultopsTree(const MultopsConfig &config, const Clock &clock)
    : clock_(clock),
      thresh_(0),
      ratio_(0),
      memmax_(config.memmax_bytes),
      fold_units_(config.fold_units),
      rng_(config.rng_seed),
      base_(nullptr),
      first_(nullptr),
      last_(nullptr),
      alloced_mem_(0),
      table_count_(0),
      counter_count_(0),
      prev_fold_epoch_(clock.now_epoch()),
      fold_runs_(0) {
    // RATIO is parsed upstream with FixedPointArg(16); invalid values are
    // clamped here (the Click element rejects them in configure()).
    double r = config.sample_ratio;
    if (!(r > 0.0)) r = 0.0;
    if (r > 1.0) r = 1.0;
    ratio_ = static_cast<uint32_t>(r * 65536.0 + 0.5);
    // "Set zoom-threshold as if ratio were 1." Computed as (t * ratio) >> 16
    // without overflow. Upstream does this in 32-bit unsigned arithmetic,
    // which wraps for THRESH >= 65536 (deviation D6).
    int64_t t = config.thresh < 0 ? 0 : config.thresh;
    int64_t rfix = static_cast<int64_t>(ratio_);
    thresh_ = (t >> 16) * rfix + (((t & 0xFFFF) * rfix) >> 16);

    base_ = new_table();
    first_ = last_ = base_;
}

MultopsTree::~MultopsTree() {
    reset();
    delete base_;
}

MultopsTree::Stats *MultopsTree::new_table() {
    Stats *s = new Stats();
    alloced_mem_ += table_bytes();
    ++table_count_;
    return s;
}

MultopsTree::Counter *MultopsTree::make_counter(Stats *s, unsigned char index,
                                                const RateEWMA2 *inherit) {
    if (memmax_ && alloced_mem_ + counter_bytes() > memmax_)
        return nullptr;
    Counter *c = inherit ? new Counter(*inherit) : new Counter(clock_.now_epoch());
    s->counter[index] = c;
    alloced_mem_ += counter_bytes();
    ++counter_count_;
    return c;
}

void MultopsTree::destroy_counter(Counter *c) {
    delete c;
    alloced_mem_ -= counter_bytes();
    --counter_count_;
}

MultopsTree::Stats *MultopsTree::destroy_table(Stats *s, bool forward) {
    // Children first (upstream ~Stats is recursive in the same order).
    for (int i = 0; i < Stats::kMaxCounters; ++i) {
        Counter *c = s->counter[i];
        if (!c) continue;
        if (c->next_level)
            destroy_table(c->next_level, forward);
        destroy_counter(c);
        s->counter[i] = nullptr;
    }
    // Unlink from the age list. Neighbours are read only now, after the
    // descendants (which may have been neighbours) were removed.
    Stats *prev = s->prev;
    Stats *next = s->next;
    if (prev) prev->next = next; else first_ = next;
    if (next) next->prev = prev; else last_ = prev;
    if (s->parent)
        s->parent->next_level = nullptr;
    delete s;
    alloced_mem_ -= table_bytes();
    --table_count_;
    return forward ? next : prev;
}

bool MultopsTree::sample() {
    // Upstream: ((click_random() >> 5) & 0xffff) <= _ratio
    if (ratio_ >= 0x10000) return true;
    return static_cast<uint32_t>(rng_() & 0xffff) <= ratio_;
}

UpdateResult MultopsTree::update(uint32_t addr, Direction dir, uint32_t value) {
    UpdateResult result;
    const unsigned idx = static_cast<unsigned>(dir);
    const uint32_t now = clock_.now_epoch();
    const uint32_t freq = clock_.epoch_frequency();
    const bool update_ewma = sample();

    // Zoom in to the deepest opened level, updating every level on the way.
    Stats *s = base_;
    Counter *c = nullptr;
    int bitshift;
    for (bitshift = 24; bitshift >= 0; bitshift -= 8) {
        unsigned char byte = static_cast<unsigned char>((addr >> bitshift) & 255);
        c = s->counter[byte];
        if (!c && !(c = make_counter(s, byte, nullptr)))
            return result;  // memory limit: stop here, like upstream
        if (update_ewma)
            c->rates.update(now, value, idx);
        // Exact per-window count: every packet, independent of RATIO sampling.
        c->window_count[idx] += value;
        result.counted = true;
        if (!c->next_level)
            break;
        s = c->next_level;
    }
    if (bitshift < 0) bitshift = 0;  // unreachable: level-3 counters never expand

    result.prefix_len = static_cast<uint8_t>(32 - bitshift);
    result.fwd_rate = c->rates.rate_per_second(0, freq);
    result.rev_rate = c->rates.rate_per_second(1, freq);

    // Expand one level if either rate reaches THRESH, this is not the last
    // byte, and memory allows a new table plus one counter.
    if ((result.fwd_rate >= thresh_ || result.rev_rate >= thresh_) && bitshift > 0 &&
        (!memmax_ || alloced_mem_ + counter_bytes() + table_bytes() <= memmax_)) {
        int child_shift = bitshift - 8;
        unsigned char next_byte = static_cast<unsigned char>((addr >> child_shift) & 255);
        Stats *t = new_table();
        if (!make_counter(t, next_byte, &c->rates)) {
            // Cannot happen given the memory check above; clean up anyway
            // without touching the age list (t was never linked).
            delete t;
            alloced_mem_ -= table_bytes();
            --table_count_;
            return result;
        }
        c->next_level = t;
        t->parent = c;
        // Append as youngest in the age list.
        last_->next = t;
        t->prev = last_;
        t->next = nullptr;
        last_ = t;
        result.expanded = true;
    }

    // Periodic fold, about once per second (per instance; see deviation D1).
    if (now - prev_fold_epoch_ >= freq) {
        fold(thresh_);
        prev_fold_epoch_ = now;
    }
    return result;
}

bool MultopsTree::below_fold_threshold(const Counter *c, int64_t thresh) const {
    if (fold_units_ == FoldUnits::UpstreamScaledPerEpoch)
        return c->rates.scaled_average(0) < thresh && c->rates.scaled_average(1) < thresh;
    const uint32_t freq = clock_.epoch_frequency();
    return c->rates.rate_per_second(0, freq) < thresh &&
           c->rates.rate_per_second(1, freq) < thresh;
}

void MultopsTree::fold(int64_t thresh) {
    ++fold_runs_;
    const bool forward = (rng_() & 1) != 0;
    const uint32_t now = clock_.now_epoch();

    // Without a memory limit, stop after freeing ~10% ("would take too long").
    std::size_t limit = memmax_;
    if (!limit)
        limit = static_cast<std::size_t>(static_cast<float>(alloced_mem_) * kFoldFactor);

    Stats *s = forward ? first_ : last_;
    while (s) {
        if (!s->parent) {  // never fold the root table
            s = forward ? s->next : s->prev;
            continue;
        }
        s->parent->rates.advance_to(now);
        if (below_fold_threshold(s->parent, thresh)) {
            Stats *neighbour = destroy_table(s, forward);
            if (alloced_mem_ < limit || !neighbour)
                break;
            s = neighbour;
            continue;
        }
        s = forward ? s->next : s->prev;
    }
}

void MultopsTree::forced_fold() {
    if (!memmax_) return;
    int64_t perc = static_cast<int64_t>(static_cast<float>(thresh_) / kFoldIncreaseFactor);
    if (perc < 1) perc = 1;  // deviation D5: upstream can loop forever when 0
    for (int64_t t = thresh_; alloced_mem_ > memmax_; t += perc) {
        if (table_count_ <= 1)  // deviation D5: only the root is left
            break;
        fold(t);
    }
}

void MultopsTree::set_memmax_bytes(std::size_t bytes) {
    memmax_ = bytes;
    if (memmax_ && alloced_mem_ > memmax_)
        forced_fold();
}

void MultopsTree::reset() {
    for (int i = 0; i < Stats::kMaxCounters; ++i) {
        Counter *c = base_->counter[i];
        if (!c) continue;
        if (c->next_level)
            destroy_table(c->next_level, true);
        destroy_counter(c);  // deviation D4: upstream forgets this accounting
        base_->counter[i] = nullptr;
    }
}

PrefixStats MultopsTree::make_record(Counter *c, uint32_t prefix, unsigned level) {
    const uint32_t freq = clock_.epoch_frequency();
    PrefixStats r;
    r.prefix_len = static_cast<uint8_t>(8 * (level + 1));
    r.prefix = r.prefix_len == 32 ? prefix : (prefix & ~(0xFFFFFFFFu >> r.prefix_len));
    r.is_leaf = (c->next_level == nullptr);
    r.fwd_rate = c->rates.rate_per_second(0, freq);
    r.rev_rate = c->rates.rate_per_second(1, freq);
    r.fwd_count = c->window_count[0];
    r.rev_count = c->window_count[1];
    return r;
}

void MultopsTree::collect(Stats *s, uint32_t prefix, unsigned level, CollectMode mode,
                          bool reset_counts, std::vector<PrefixStats> &out) {
    const uint32_t now = clock_.now_epoch();
    for (int i = 0; i < Stats::kMaxCounters; ++i) {
        Counter *c = s->counter[i];
        if (!c) continue;
        uint32_t p = prefix | (static_cast<uint32_t>(i) << (24 - 8 * level));
        c->rates.advance_to(now);  // account for idle time before reading
        bool active = c->rates.scaled_average(0) > 0 || c->rates.scaled_average(1) > 0 ||
                      c->window_count[0] > 0 || c->window_count[1] > 0;
        if (active && (mode == CollectMode::AllActive || c->next_level == nullptr))
            out.push_back(make_record(c, p, level));
        if (reset_counts)
            c->window_count[0] = c->window_count[1] = 0;
        if (c->next_level)
            collect(c->next_level, p, level + 1, mode, reset_counts, out);
    }
}

std::vector<PrefixStats> MultopsTree::collect_stats(CollectMode mode, bool reset_window_counts) {
    std::vector<PrefixStats> out;
    collect(base_, 0, 0, mode, reset_window_counts, out);
    return out;
}

std::vector<PrefixStats> MultopsTree::lookup(uint32_t addr) {
    std::vector<PrefixStats> out;
    const uint32_t now = clock_.now_epoch();
    Stats *s = base_;
    for (int bitshift = 24, level = 0; bitshift >= 0; bitshift -= 8, ++level) {
        Counter *c = s->counter[(addr >> bitshift) & 255];
        if (!c) break;
        c->rates.advance_to(now);
        out.push_back(make_record(c, addr, static_cast<unsigned>(level)));
        if (!c->next_level) break;
        s = c->next_level;
    }
    return out;
}

void MultopsTree::look(Stats *s, const std::string &ip, std::string &out) {
    const uint32_t now = clock_.now_epoch();
    const uint32_t freq = clock_.epoch_frequency();
    char buf[64];
    for (int i = 0; i < Stats::kMaxCounters; ++i) {
        Counter *c = s->counter[i];
        if (!c) continue;
        c->rates.advance_to(now);
        if (c->rates.scaled_average(0) <= 0 && c->rates.scaled_average(1) <= 0)
            continue;
        std::string this_ip = ip.empty() ? std::to_string(i) : ip + "." + std::to_string(i);
        std::snprintf(buf, sizeof(buf), "\t%.3f\t%.3f\n", c->rates.rate_per_second_exact(0, freq),
                      c->rates.rate_per_second_exact(1, freq));
        out += this_ip + buf;
        if (c->next_level)
            look(c->next_level, "\t" + this_ip, out);
    }
}

std::string MultopsTree::look() {
    std::string out;
    look(base_, "", out);
    return out;
}

std::string MultopsTree::check_invariants() const {
    std::ostringstream err;
    // 1. Walk the tree.
    std::size_t tables = 0, counters = 0;
    std::set<const Stats *> reachable;
    std::vector<const Stats *> stack(1, base_);
    if (base_->parent) err << "root has a parent; ";
    while (!stack.empty()) {
        const Stats *s = stack.back();
        stack.pop_back();
        reachable.insert(s);
        ++tables;
        for (int i = 0; i < Stats::kMaxCounters; ++i) {
            const Counter *c = s->counter[i];
            if (!c) continue;
            ++counters;
            if (c->next_level) {
                if (c->next_level->parent != c) err << "child table parent link broken; ";
                stack.push_back(c->next_level);
            }
        }
    }
    // 2. Walk the age list.
    std::size_t listed = 0;
    if (first_ != base_) err << "root is not first in the age list; ";
    const Stats *prev = nullptr;
    for (const Stats *s = first_; s; s = s->next) {
        if (s->prev != prev) err << "age list prev link broken; ";
        if (!reachable.count(s)) err << "age list holds an unreachable table; ";
        prev = s;
        if (++listed > tables + 1) { err << "age list too long or cyclic; "; break; }
    }
    if (last_ != prev) err << "last_ is not the list tail; ";
    if (listed != tables) err << "age list size " << listed << " != tables " << tables << "; ";
    // 3. Accounting.
    if (tables != table_count_) err << "table_count_ mismatch; ";
    if (counters != counter_count_) err << "counter_count_ mismatch; ";
    std::size_t expected = tables * table_bytes() + counters * counter_bytes();
    if (expected != alloced_mem_)
        err << "alloced_mem_ " << alloced_mem_ << " != expected " << expected << "; ";
    return err.str();
}

std::string ipv4_to_string(uint32_t a) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (a >> 24) & 255, (a >> 16) & 255,
                  (a >> 8) & 255, a & 255);
    return buf;
}

bool parse_ipv4(const std::string &text, uint32_t &out) {
    unsigned b[4];
    char tail;
    if (std::sscanf(text.c_str(), "%u.%u.%u.%u%c", &b[0], &b[1], &b[2], &b[3], &tail) != 4)
        return false;
    for (int i = 0; i < 4; ++i)
        if (b[i] > 255) return false;
    out = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
    return true;
}

std::string prefix_to_string(uint32_t prefix, unsigned len) {
    return ipv4_to_string(prefix) + "/" + std::to_string(len);
}

}  // namespace multops
