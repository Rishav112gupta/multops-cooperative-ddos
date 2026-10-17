cmake_minimum_required(VERSION 3.10)
project(multops_cooperative_ddos CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(MULTOPS_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
set(CLICK_SRC "" CACHE PATH "Path to a Click source tree (enables differential tests against upstream headers)")

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion)
if(MULTOPS_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

# Core library (no Click dependency).
add_library(multops STATIC multops/src/multops_tree.cpp)
target_include_directories(multops PUBLIC multops/include)

# Unit tests.
enable_testing()
foreach(t test_rate_ewma test_multops_tree)
  add_executable(${t} tests/cpp/${t}.cpp)
  target_link_libraries(${t} multops)
  add_test(NAME ${t} COMMAND ${t})
endforeach()

# Differential test: our RateEWMA2 vs upstream Click's ewma.hh (header-only use).
if(CLICK_SRC)
  if(NOT EXISTS "${CLICK_SRC}/include/click/config.h")
    message(FATAL_ERROR "CLICK_SRC must be a configured Click tree (include/click/config.h missing)")
  endif()
  add_executable(diff_upstream_ewma tests/cpp/diff_upstream_ewma.cpp)
  target_include_directories(diff_upstream_ewma PRIVATE "${CLICK_SRC}/include")
  target_compile_definitions(diff_upstream_ewma PRIVATE CLICK_USERLEVEL=1)
  target_compile_options(diff_upstream_ewma PRIVATE -w)
  target_link_libraries(diff_upstream_ewma multops)
  add_test(NAME diff_upstream_ewma COMMAND diff_upstream_ewma)
endif()

# Offline replay tool (debugging and trace experiments).
add_executable(multops_replay tools/multops_replay.cpp)
target_link_libraries(multops_replay multops)

# Smoke test of the replay tool on a small deterministic trace.
add_test(NAME replay_sample_trace
         COMMAND multops_replay --thresh 100 --interval-ms 1000 ${CMAKE_SOURCE_DIR}/tests/data/sample_trace.csv)
set_tests_properties(replay_sample_trace PROPERTIES PASS_REGULAR_EXPRESSION "invariants=ok")
