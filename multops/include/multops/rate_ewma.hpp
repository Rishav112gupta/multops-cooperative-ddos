// rate_ewma.hpp -- port of Click's RateEWMAX as used by IPRateMonitor.
//
// Upstream: include/click/ewma.hh, instantiated in elements/ip/ipratemon.hh as
//   RateEWMAX<FixedEWMAXParameters<stability_shift = 5, scale = 10>>
// with rate_count = 2 (index 0 = forward rate, index 1 = reverse rate).
//
// Semantics reproduced exactly:
//  * Samples are accumulated per epoch in _current[i].
//  * When the epoch changes, the finished epoch's sample is folded into the
//    average:  avg += ((x << 10) + 16 - avg) >> 5   (alpha = 1/32)
//    and every fully idle epoch in between applies an observation of 0
//    (if 100 or more epochs passed, the average is set to 0 directly).
//  * The average is stored as an unsigned 32-bit value with 10 fraction bits,
//    in units of "samples per epoch".
//
// The only intentional difference: rate_per_second() widens to 64 bits
// before multiplying by the epoch frequency. Upstream does this multiply in
// a 32-bit int (ipratemon.hh, IPRateMonitor::update), which overflows once a
// rate exceeds about 2.1 million units/s, i.e. ~2.1 MB/s in BYTES mode.
// Below that limit both give identical results. See
// docs/PHASE2_MULTOPS_VERIFICATION.md (D3).

#ifndef MULTOPS_RATE_EWMA_HPP
#define MULTOPS_RATE_EWMA_HPP

#include <cstdint>

namespace multops {

class RateEWMA2 {
  public:
    enum : unsigned { kStabilityShift = 5, kScale = 10, kRateCount = 2 };
    enum : uint32_t { kCompensation = 1u << (kStabilityShift - 1) };

    explicit RateEWMA2(uint32_t now_epoch = 0) : current_epoch_(now_epoch) {
        for (unsigned i = 0; i < kRateCount; ++i) {
            current_[i] = 0;
            avg_[i] = 0;
        }
    }

    // Upstream RateEWMAX::update(delta, ratenum): close any finished epochs,
    // then add delta to the current epoch's sample for rate `index`.
    void update(uint32_t now_epoch, uint32_t delta, unsigned index) {
        advance_to(now_epoch);
        current_[index] += delta;
    }

    // Upstream calls update(0) purely to account for elapsed time before
    // reading an average; this is that operation.
    void advance_to(uint32_t now_epoch) {
        uint32_t jj = current_epoch_;
        if (now_epoch != jj) {
            for (unsigned i = 0; i < kRateCount; ++i) {
                direct_update(avg_[i], current_[i]);
                if (jj + 1 != now_epoch)
                    direct_update_n(avg_[i], 0, now_epoch - jj - 1);
                current_[i] = 0;
            }
            current_epoch_ = now_epoch;
        }
    }

    // Average in samples per epoch with kScale fraction bits (signed, as
    // upstream's scaled_average() returns int).
    int32_t scaled_average(unsigned index) const {
        return static_cast<int32_t>(avg_[index]);
    }

    // Rate in samples per second, truncated, as computed in upstream
    // IPRateMonitor::update(): (scaled_average * freq) >> scale.
    int64_t rate_per_second(unsigned index, uint32_t epoch_frequency) const {
        return (static_cast<int64_t>(scaled_average(index)) * epoch_frequency) >> kScale;
    }

    // Same rate as a floating-point value (no truncation).
    double rate_per_second_exact(unsigned index, uint32_t epoch_frequency) const {
        return static_cast<double>(scaled_average(index)) * epoch_frequency /
               static_cast<double>(1u << kScale);
    }

    uint32_t current_epoch() const { return current_epoch_; }
    uint32_t pending_sample(unsigned index) const { return current_[index]; }

  private:
    // DirectEWMAX::update with HAVE_ARITHMETIC_RIGHT_SHIFT (true on x86/ARM).
    static void direct_update(uint32_t &avg, uint32_t x) {
        uint32_t x_scaled = (x << kScale) + kCompensation;
        avg += static_cast<uint32_t>(arith_shift(static_cast<int32_t>(x_scaled - avg)));
    }

    // DirectEWMAX::update_n.
    static void direct_update_n(uint32_t &avg, uint32_t x, uint32_t n) {
        uint32_t x_scaled = x << kScale;
        if (n >= 100) {
            avg = x_scaled;
        } else {
            x_scaled += kCompensation;
            for (; n > 0; --n)
                avg += static_cast<uint32_t>(arith_shift(static_cast<int32_t>(x_scaled - avg)));
        }
    }

    // Arithmetic right shift that is well-defined for negative values in
    // every C++ standard (floor division by 2^kStabilityShift).
    static int32_t arith_shift(int32_t v) {
        return v >= 0 ? (v >> kStabilityShift)
                      : -static_cast<int32_t>(((-static_cast<int64_t>(v)) + (1 << kStabilityShift) - 1)
                                              >> kStabilityShift);
    }

    uint32_t current_epoch_;
    uint32_t current_[kRateCount];
    uint32_t avg_[kRateCount];
};

}  // namespace multops

#endif
