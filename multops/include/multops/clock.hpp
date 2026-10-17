// clock.hpp -- epoch sources for the MULTOPS rate estimators.
//
// Upstream Click IPRateMonitor measures time in "epochs" of
// click_jiffies() >> 3. At user level CLICK_HZ = 1000, so one epoch is 8 ms
// and there are 125 epochs per second. The core library takes time from a
// Clock so that unit tests can drive time deterministically (ManualClock),
// while the Click element supplies a clock backed by click_jiffies().

#ifndef MULTOPS_CLOCK_HPP
#define MULTOPS_CLOCK_HPP

#include <chrono>
#include <cstdint>

namespace multops {

class Clock {
  public:
    virtual ~Clock() {}
    // Current epoch number. Must be monotonically non-decreasing
    // (wrap-around at 2^32 is handled the same way as upstream).
    virtual uint32_t now_epoch() const = 0;
    // Number of epochs per second (used to convert rates to per-second).
    virtual uint32_t epoch_frequency() const = 0;
};

// Upstream user-level constants: CLICK_HZ = 1000, epoch = jiffies >> 3.
enum : uint32_t { kUpstreamEpochFrequency = 1000 >> 3 };  // 125

// Fully controlled clock for tests and offline trace replay.
class ManualClock : public Clock {
  public:
    explicit ManualClock(uint32_t frequency = kUpstreamEpochFrequency,
                         uint32_t start_epoch = 0)
        : frequency_(frequency), epoch_(start_epoch) {}

    uint32_t now_epoch() const override { return epoch_; }
    uint32_t epoch_frequency() const override { return frequency_; }

    void set_epoch(uint32_t e) { epoch_ = e; }
    void advance(uint32_t epochs) { epoch_ += epochs; }
    // Advance by a duration in milliseconds, rounded down to whole epochs.
    void advance_ms(uint64_t ms) {
        epoch_ += static_cast<uint32_t>(ms * frequency_ / 1000);
    }

  private:
    uint32_t frequency_;
    uint32_t epoch_;
};

// Wall-clock (monotonic) clock with upstream-compatible epoch length.
class SteadyClock : public Clock {
  public:
    SteadyClock() : origin_(std::chrono::steady_clock::now()) {}

    uint32_t now_epoch() const override {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - origin_)
                      .count();
        return static_cast<uint32_t>(static_cast<uint64_t>(ms) >> 3);
    }
    uint32_t epoch_frequency() const override { return kUpstreamEpochFrequency; }

  private:
    std::chrono::steady_clock::time_point origin_;
};

}  // namespace multops

#endif
