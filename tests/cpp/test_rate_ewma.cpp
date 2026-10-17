// Unit tests for RateEWMA2 (port of Click RateEWMAX<FixedEWMAXParameters<5,10>>).
// Expected values are derived by hand from the upstream formulas:
//   avg += ((x << 10) + 16 - avg) >> 5      per closed epoch
//   n >= 100 idle epochs  ->  avg = 0

#include "mini_test.hpp"
#include "multops/rate_ewma.hpp"

using multops::RateEWMA2;

TEST(ewma_starts_at_zero) {
    RateEWMA2 e(10);
    CHECK_EQ(e.scaled_average(0), 0);
    CHECK_EQ(e.scaled_average(1), 0);
    CHECK_EQ(e.current_epoch(), 10u);
}

TEST(ewma_sample_applied_only_when_epoch_closes) {
    RateEWMA2 e(0);
    e.update(0, 8, 0);
    CHECK_EQ(e.scaled_average(0), 0);       // epoch 0 still open
    CHECK_EQ(e.pending_sample(0), 8u);
    e.advance_to(1);
    // (8 << 10) + 16 = 8208; 8208 >> 5 = 256
    CHECK_EQ(e.scaled_average(0), 256);
    CHECK_EQ(e.scaled_average(1), 0);       // rate 1 got observation 0: (0+16)>>5 = 0
}

TEST(ewma_two_rates_are_independent) {
    RateEWMA2 e(0);
    e.update(0, 32, 0);
    e.update(0, 64, 1);
    e.advance_to(1);
    CHECK_EQ(e.scaled_average(0), ((32 << 10) + 16) >> 5);
    CHECK_EQ(e.scaled_average(1), ((64 << 10) + 16) >> 5);
}

TEST(ewma_idle_gap_applies_zero_observations) {
    RateEWMA2 e(0);
    e.update(0, 32, 0);
    e.advance_to(1);
    int32_t a1 = e.scaled_average(0);       // 1024
    CHECK_EQ(a1, 1024);
    e.advance_to(4);                        // closes epoch 1 (sample 0) + 2 idle epochs
    // three zero observations: a += (16 - a) >> 5, computed with floor shift
    int32_t a = a1;
    for (int i = 0; i < 3; ++i) {
        int32_t d = 16 - a;
        a += d >= 0 ? (d >> 5) : -((-d + 31) >> 5);
    }
    CHECK_EQ(e.scaled_average(0), a);
    CHECK(e.scaled_average(0) < a1);
}

TEST(ewma_gap_of_100_or_more_resets_to_zero) {
    RateEWMA2 e(0);
    for (uint32_t t = 0; t < 50; ++t) e.update(t, 100, 0);
    e.advance_to(50);
    CHECK(e.scaled_average(0) > 0);
    e.advance_to(50 + 1 + 100);             // 100 idle epochs after closing epoch 50
    CHECK_EQ(e.scaled_average(0), 0);
}

TEST(ewma_converges_to_constant_rate) {
    // k samples per epoch -> fixed point avg* with ((k<<10)+16-avg*)>>5 == 0,
    // i.e. avg* in [ (k<<10)+16-31 , (k<<10)+16 ].
    const uint32_t k = 80;                  // 80/epoch = 10 000 per second
    RateEWMA2 e(0);
    for (uint32_t t = 0; t < 2000; ++t) e.update(t, k, 0);
    e.advance_to(2000);
    int32_t lo = static_cast<int32_t>((k << 10) + 16 - 31);
    int32_t hi = static_cast<int32_t>((k << 10) + 16);
    CHECK(e.scaled_average(0) >= lo);
    CHECK(e.scaled_average(0) <= hi);
    // The fixed point sits just below k<<10, so 10 000 pps reads as 9998.
    CHECK(e.rate_per_second(0, 125) >= (static_cast<int64_t>(lo) * 125 >> 10));
    CHECK(e.rate_per_second(0, 125) <= (static_cast<int64_t>(hi) * 125 >> 10));
    CHECK_NEAR(e.rate_per_second(0, 125), 10000, 3);
}

TEST(ewma_time_constant_is_32_epochs) {
    // After a step from 0 to k, the average reaches 1 - (31/32)^n of k.
    RateEWMA2 e(0);
    const uint32_t k = 1000;
    for (uint32_t t = 0; t < 32; ++t) e.update(t, k, 0);
    e.advance_to(32);
    double expected = 1.0 - std::pow(31.0 / 32.0, 32);  // ~0.638
    CHECK_NEAR(e.scaled_average(0) / 1024.0 / k, expected, 0.01);
}

TEST(ewma_rate_conversion_matches_upstream_formula) {
    RateEWMA2 e(0);
    e.update(0, 8, 0);
    e.advance_to(1);                        // scaled 256
    CHECK_EQ(e.rate_per_second(0, 125), (256 * 125) >> 10);  // 31
    CHECK_NEAR(e.rate_per_second_exact(0, 125), 256.0 * 125 / 1024, 1e-9);
}

TEST(ewma_rate_conversion_does_not_overflow_32_bits) {
    // ~2^31 scaled: upstream's int multiply by 125 would overflow here.
    RateEWMA2 e(0);
    for (uint32_t t = 0; t < 3000; ++t) e.update(t, 2000000, 0);  // 2M per epoch
    e.advance_to(3000);
    int64_t r = e.rate_per_second(0, 125);
    CHECK(r > 0);
    CHECK_NEAR(static_cast<double>(r), 2000000.0 * 125, 2000000.0 * 125 * 0.001);
    // What upstream's 32-bit arithmetic would compute (two's complement wrap).
    int64_t wide = static_cast<int64_t>(e.scaled_average(0)) * 125;
    int32_t wrapped = static_cast<int32_t>(static_cast<uint32_t>(wide));
    CHECK(static_cast<int64_t>(wrapped) != wide);  // demonstrates the upstream overflow
}

TEST(ewma_copy_inherits_full_state) {
    RateEWMA2 e(0);
    for (uint32_t t = 0; t < 10; ++t) e.update(t, 5, 1);
    RateEWMA2 copy(e);
    CHECK_EQ(copy.scaled_average(1), e.scaled_average(1));
    CHECK_EQ(copy.pending_sample(1), e.pending_sample(1));
    CHECK_EQ(copy.current_epoch(), e.current_epoch());
}

TEST(ewma_epoch_wraparound) {
    RateEWMA2 e(0xFFFFFFFEu);
    e.update(0xFFFFFFFEu, 32, 0);
    e.advance_to(1);                        // epochs FFFFFFFE -> 1: 2 idle epochs between
    int32_t a = ((32 << 10) + 16) >> 5;     // 1024
    for (int i = 0; i < 2; ++i) {
        int32_t d = 16 - a;
        a += d >= 0 ? (d >> 5) : -((-d + 31) >> 5);
    }
    CHECK_EQ(e.scaled_average(0), a);
}

MINI_TEST_MAIN
