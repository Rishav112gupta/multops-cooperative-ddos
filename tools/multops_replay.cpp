// multops_replay -- feed a packet trace through MultopsTree offline.
//
// Input (CSV, one packet per line, '#' comments allowed):
//     time_ms,dir,addr,value
//   time_ms  non-decreasing milliseconds since trace start
//   dir      F (forward: input 0, addr = source) or R (reverse: input 1, addr = destination)
//   addr     dotted IPv4 address
//   value    1 for PACKETS mode, IP length for BYTES mode (optional, default 1)
//
// Output (CSV): one block per export interval, like the Click element's timer:
//     interval_end_ms,prefix,len,leaf,fwd_rate,rev_rate,fwd_count,rev_count
// followed by a summary line on stderr.
//
// Usage:
//   multops_replay [--thresh N] [--ratio R] [--memory-kb K] [--interval-ms M]
//                  [--mode all|leaves] [--fold-units upstream|persec] [--seed S] [trace.csv]

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "multops/multops_tree.hpp"

using namespace multops;

namespace {

void usage() {
    std::fprintf(stderr,
                 "usage: multops_replay [--thresh N] [--ratio R] [--memory-kb K] [--interval-ms M]\n"
                 "                      [--mode all|leaves] [--fold-units upstream|persec]\n"
                 "                      [--seed S] [trace.csv]\n");
}

void emit(MultopsTree &tree, CollectMode mode, uint64_t t_ms) {
    for (const PrefixStats &r : tree.collect_stats(mode, true)) {
        std::printf("%llu,%s,%u,%d,%lld,%lld,%llu,%llu\n", static_cast<unsigned long long>(t_ms),
                    ipv4_to_string(r.prefix).c_str(), r.prefix_len, r.is_leaf ? 1 : 0,
                    static_cast<long long>(r.fwd_rate), static_cast<long long>(r.rev_rate),
                    static_cast<unsigned long long>(r.fwd_count),
                    static_cast<unsigned long long>(r.rev_count));
    }
}

}  // namespace

int main(int argc, char **argv) {
    MultopsConfig config;
    config.thresh = 1000;
    uint64_t interval_ms = 1000;
    CollectMode mode = CollectMode::AllActive;
    const char *path = nullptr;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> const char * {
            if (i + 1 >= argc) { usage(); std::exit(2); }
            return argv[++i];
        };
        if (a == "--thresh") config.thresh = std::atoll(next());
        else if (a == "--ratio") config.sample_ratio = std::atof(next());
        else if (a == "--memory-kb") config.memmax_bytes = memmax_from_kb(std::strtoull(next(), nullptr, 10));
        else if (a == "--interval-ms") interval_ms = std::strtoull(next(), nullptr, 10);
        else if (a == "--seed") config.rng_seed = std::strtoull(next(), nullptr, 10);
        else if (a == "--mode") {
            std::string m = next();
            if (m == "all") mode = CollectMode::AllActive;
            else if (m == "leaves") mode = CollectMode::LeavesOnly;
            else { usage(); return 2; }
        } else if (a == "--fold-units") {
            std::string m = next();
            if (m == "upstream") config.fold_units = FoldUnits::UpstreamScaledPerEpoch;
            else if (m == "persec") config.fold_units = FoldUnits::PerSecond;
            else { usage(); return 2; }
        } else if (a == "-h" || a == "--help") { usage(); return 0; }
        else if (!a.empty() && a[0] == '-') { usage(); return 2; }
        else path = argv[i];
    }
    std::string err;
    if (!MultopsTree::validate(config, &err) || interval_ms == 0) {
        std::fprintf(stderr, "invalid configuration: %s\n", err.empty() ? "interval must be > 0" : err.c_str());
        return 2;
    }

    std::ifstream file;
    std::istream *in = &std::cin;
    if (path) {
        file.open(path);
        if (!file) { std::fprintf(stderr, "cannot open %s\n", path); return 1; }
        in = &file;
    }

    ManualClock clock;  // epoch = ms >> 3, 125 epochs/s (upstream user level)
    MultopsTree tree(config, clock);
    std::printf("interval_end_ms,prefix,len,leaf,fwd_rate,rev_rate,fwd_count,rev_count\n");

    uint64_t next_export = interval_ms, last_ms = 0, packets = 0, lineno = 0;
    std::string line;
    while (std::getline(*in, line)) {
        ++lineno;
        if (line.empty() || line[0] == '#') continue;
        std::stringstream ss(line);
        std::string f_time, f_dir, f_addr, f_value;
        std::getline(ss, f_time, ',');
        std::getline(ss, f_dir, ',');
        std::getline(ss, f_addr, ',');
        std::getline(ss, f_value, ',');
        uint32_t addr;
        if (f_time.empty() || (f_dir != "F" && f_dir != "R") || !parse_ipv4(f_addr, addr)) {
            std::fprintf(stderr, "line %llu: malformed: %s\n", static_cast<unsigned long long>(lineno), line.c_str());
            return 1;
        }
        uint64_t t = std::strtoull(f_time.c_str(), nullptr, 10);
        if (t < last_ms) {
            std::fprintf(stderr, "line %llu: time goes backwards\n", static_cast<unsigned long long>(lineno));
            return 1;
        }
        while (t >= next_export) {  // timer fires before this packet
            clock.set_epoch(static_cast<uint32_t>(next_export >> 3));
            emit(tree, mode, next_export);
            next_export += interval_ms;
        }
        last_ms = t;
        clock.set_epoch(static_cast<uint32_t>(t >> 3));
        uint32_t value = f_value.empty() ? 1u : static_cast<uint32_t>(std::strtoul(f_value.c_str(), nullptr, 10));
        tree.update(addr, f_dir == "F" ? Direction::Forward : Direction::Reverse, value);
        ++packets;
    }
    clock.set_epoch(static_cast<uint32_t>(next_export >> 3));
    emit(tree, mode, next_export);

    std::fprintf(stderr, "packets=%llu tables=%zu counters=%zu memory_bytes=%zu folds=%llu invariants=%s\n",
                 static_cast<unsigned long long>(packets), tree.table_count(), tree.counter_count(),
                 tree.memory_bytes(), static_cast<unsigned long long>(tree.fold_runs()),
                 tree.check_invariants().empty() ? "ok" : tree.check_invariants().c_str());
    return 0;
}
