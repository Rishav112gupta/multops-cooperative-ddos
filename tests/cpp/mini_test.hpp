// mini_test.hpp -- minimal dependency-free unit test harness.
//
//   TEST(name) { CHECK(cond); CHECK_EQ(a, b); CHECK_NEAR(a, b, tol); REQUIRE(cond); }
//
// Each test runs in registration order; the runner prints one line per test
// and returns non-zero if any check failed. Filter with: ./test_binary <substring>

#ifndef MINI_TEST_HPP
#define MINI_TEST_HPP

#include <cmath>
#include <cstdio>
#include <cstring>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace mini_test {

struct TestCase {
    const char *name;
    std::function<void()> fn;
};

inline std::vector<TestCase> &registry() {
    static std::vector<TestCase> tests;
    return tests;
}

struct State {
    int failures = 0;
    const char *current = "";
};

inline State &state() {
    static State s;
    return s;
}

struct Registrar {
    Registrar(const char *name, std::function<void()> fn) { registry().push_back({name, fn}); }
};

struct RequireFailed {};

inline void report(const char *file, int line, const std::string &msg) {
    ++state().failures;
    std::printf("    FAIL %s:%d: %s\n", file, line, msg.c_str());
}

template <typename A, typename B>
std::string describe_eq(const char *ea, const char *eb, const A &a, const B &b) {
    std::ostringstream os;
    os << ea << " == " << eb << "  (" << a << " vs " << b << ")";
    return os.str();
}

inline int run_all(int argc, char **argv) {
    const char *filter = argc > 1 ? argv[1] : nullptr;
    int ran = 0, failed_tests = 0;
    for (auto &t : registry()) {
        if (filter && !std::strstr(t.name, filter)) continue;
        int before = state().failures;
        state().current = t.name;
        try {
            t.fn();
        } catch (const RequireFailed &) {
            // already reported
        } catch (const std::exception &e) {
            report(__FILE__, __LINE__, std::string("unexpected exception: ") + e.what());
        }
        ++ran;
        bool ok = state().failures == before;
        if (!ok) ++failed_tests;
        std::printf("[%s] %s\n", ok ? " OK " : "FAIL", t.name);
    }
    std::printf("\n%d test(s) run, %d failed, %d failed check(s)\n", ran, failed_tests,
                state().failures);
    return failed_tests == 0 && ran > 0 ? 0 : 1;
}

}  // namespace mini_test

#define MT_CONCAT2(a, b) a##b
#define MT_CONCAT(a, b) MT_CONCAT2(a, b)

#define TEST(name)                                                              \
    static void name();                                                         \
    static mini_test::Registrar MT_CONCAT(registrar_, name)(#name, name);       \
    static void name()

#define CHECK(cond)                                                             \
    do {                                                                        \
        if (!(cond)) mini_test::report(__FILE__, __LINE__, "CHECK(" #cond ")"); \
    } while (0)

#define REQUIRE(cond)                                                             \
    do {                                                                          \
        if (!(cond)) {                                                            \
            mini_test::report(__FILE__, __LINE__, "REQUIRE(" #cond ")");          \
            throw mini_test::RequireFailed();                                     \
        }                                                                         \
    } while (0)

#define CHECK_EQ(a, b)                                                                     \
    do {                                                                                   \
        auto mt_a_ = (a);                                                                  \
        auto mt_b_ = (b);                                                                  \
        if (!(mt_a_ == mt_b_))                                                             \
            mini_test::report(__FILE__, __LINE__, mini_test::describe_eq(#a, #b, mt_a_, mt_b_)); \
    } while (0)

#define CHECK_NEAR(a, b, tol)                                                             \
    do {                                                                                  \
        double mt_a_ = static_cast<double>(a), mt_b_ = static_cast<double>(b);            \
        if (!(std::fabs(mt_a_ - mt_b_) <= (tol))) {                                       \
            std::ostringstream mt_os_;                                                    \
            mt_os_ << #a " ~= " #b " (" << mt_a_ << " vs " << mt_b_ << ", tol " << (tol) << ")"; \
            mini_test::report(__FILE__, __LINE__, mt_os_.str());                          \
        }                                                                                 \
    } while (0)

#define MINI_TEST_MAIN \
    int main(int argc, char **argv) { return mini_test::run_all(argc, argv); }

#endif
