// Differential test: multops::RateEWMA2 vs. upstream Click RateEWMAX, using
// the exact parameterisation of IPRateMonitor (stability shift 5, scale 10,
// rate_count 2). Both are driven with the same random sequence of samples and
// epoch advances; every scaled average must match bit-for-bit.
//
// Built only when CMake is given -DCLICK_SRC=<configured Click tree>.

#include <click/config.h>
#include <click/ewma.hh>

#include <cstdio>
#include <random>

#include "multops/rate_ewma.hpp"

static unsigned g_epoch = 0;

CLICK_USING_DECLS
struct UpstreamParams : public FixedEWMAXParameters<5, 10> {
    enum { rate_count = 2 };
    static unsigned epoch() { return g_epoch; }
    static unsigned epoch_frequency() { return 125; }
};
typedef RateEWMAX<UpstreamParams> UpstreamEWMA;

int main() {
    std::mt19937 rng(2026);
    long mismatches = 0, comparisons = 0;
    for (int trial = 0; trial < 200; ++trial) {
        g_epoch = (trial % 2) ? 0xFFFFFF00u : static_cast<unsigned>(rng());  // include wrap-around
        UpstreamEWMA up;
        multops::RateEWMA2 ours(g_epoch);
        for (int step = 0; step < 5000; ++step) {
            unsigned r = rng() % 100;
            if (r < 70) {
                unsigned idx = rng() & 1;
                unsigned delta = (rng() % 4 == 0) ? rng() % 5000 : rng() % 20;
                up.update(static_cast<int>(delta), idx);
                ours.update(g_epoch, delta, idx);
            } else if (r < 97) {
                g_epoch += 1 + rng() % 3;
            } else {
                g_epoch += 50 + rng() % 120;   // exercises update_n and the n >= 100 reset
            }
            if (rng() % 4 == 0) {
                up.update(0, 0);                // upstream idiom to account for time
                ours.advance_to(g_epoch);
                for (unsigned i = 0; i < 2; ++i) {
                    ++comparisons;
                    if (up.scaled_average(i) != ours.scaled_average(i)) {
                        if (++mismatches <= 5)
                            std::printf("mismatch trial %d step %d idx %u: upstream %d ours %d\n",
                                        trial, step, i, up.scaled_average(i), ours.scaled_average(i));
                    }
                }
            }
        }
    }
    std::printf("diff_upstream_ewma: %ld comparisons, %ld mismatches\n", comparisons, mismatches);
    return mismatches == 0 && comparisons > 0 ? 0 : 1;
}
