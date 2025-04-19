// RUN: %gen_compdb %s > %t.json
// RUN: rm -rf %t.output
// RUN: mkdir -p %t.output
// RUN: %clang_exception_scan --ast-based %t.json %t.output
// RUN: cat %t.output/definite_results.txt | FileCheck %s

#include "Inputs/stdexcept.h"

// CHECK: Functions that could be marked noexcept, but are not:

// Basic function that doesn't throw
// CHECK: c:@F@empty# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
void empty() {}

// Function that already has noexcept
void empty_already_noexcept() noexcept {}

// Function that returns a value but doesn't throw
// CHECK: c:@F@return_int# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
int return_int() { return 0; }

// Function that already has noexcept
int return_int_already_noexcept() noexcept { return 0; }

// Function that throws an exception
void throw_runtime_error() { throw std::runtime_error("error"); }

// Function that catches all thrown exceptions
// CHECK: c:@F@catches_all_thrown_exceptions# in
// {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
void catches_all_thrown_exceptions() {
  try {
    throw_runtime_error();
  } catch (std::runtime_error) {
  }
}

// Function that already has noexcept
void catches_all_thrown_exceptions_already_noexcept() noexcept {
  try {
    throw_runtime_error();
  } catch (std::runtime_error) {
  }
}

// Function that catches all exceptions with catch-all
// CHECK: c:@F@catches_all_thrown_exceptions_with_catch_all# in
// {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
void catches_all_thrown_exceptions_with_catch_all() {
  try {
    throw_runtime_error();
  } catch (...) {
  }
}

// Function that already has noexcept
void catches_all_thrown_exceptions_with_catch_all_already_noexcept() noexcept {
  try {
    throw_runtime_error();
  } catch (...) {
  }
}

// Function that catches the wrong exception type
void catches_wrong_exception() {
  try {
    throw_runtime_error();
  } catch (int) {
  }
}

// Function with unknown implementation
int function_with_unknown_implementation();

// Function that calls an unknown function
// CHECK-NOT: c:@F@calls_unknown_function# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
void calls_unknown_function() { function_with_unknown_implementation(); }

// Function that uses a builtin function
// CHECK: c:@F@uses_builtin#I# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
int uses_builtin(int x) {
  return __builtin_bswap32(x);
}

// Function that uses a builtin but also calls an unknown function
// CHECK-NOT: c:@F@uses_builtin_with_unknown#I# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
int uses_builtin_with_unknown(int x) {
  int y = __builtin_bswap32(x);
  function_with_unknown_implementation();
  return y;
}

// Function that calls functions in different orders
// CHECK-NOT: c:@F@order_of_function_calls#I# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
int order_of_function_calls() {
  int a = function_with_unknown_implementation();
  int b = __builtin_bswap32(a);
  return b;
}

// Nested try-catch blocks
// CHECK: c:@F@nested_try_catch# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
void nested_try_catch() {
  try {
    try {
      throw_runtime_error();
    } catch (std::runtime_error) {
      // Inner exception caught
    }
  } catch (...) {
    // Outer catch-all
  }
}

// Nested try-catch with rethrow in catch block
// CHECK: c:@F@nested_try_catch_with_rethrow# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
void nested_try_catch_with_rethrow() {
  try {
    try {
      throw_runtime_error();
    } catch (std::runtime_error) {
      // Inner exception caught and rethrown
      throw;
    }
  } catch (std::runtime_error) {
    // Outer exception caught
  }
}

// Nested try-catch with rethrow of a different exception
// CHECK: c:@F@nested_try_catch_with_different_rethrow# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
void nested_try_catch_with_different_rethrow() {
  try {
    try {
      throw_runtime_error();
    } catch (std::runtime_error) {
      // Inner exception caught and a different exception thrown
      throw std::logic_error("transformed exception");
    }
  } catch (std::logic_error) {
    // Outer exception caught
  }
}

// Function with conditional throw
// CHECK-NOT: c:@F@conditional_throw#I# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
void conditional_throw(int x) {
  if (x > 0) {
    throw std::runtime_error("positive");
  }
}

// Function with conditional throw that's always caught
// CHECK: c:@F@conditional_throw_always_caught#I# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
void conditional_throw_always_caught(int x) {
  try {
    if (x > 0) {
      throw std::runtime_error("positive");
    }
  } catch (std::runtime_error) {
    // Exception caught
  }
}

// Function with rethrow in a catch block
// CHECK-NOT: c:@F@rethrow_in_catch# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
void rethrow_in_catch() {
  try {
    throw_runtime_error();
  } catch (std::runtime_error) {
    throw; // Rethrow the same exception
  }
}

// Function with rethrow of a different exception
// CHECK-NOT: c:@F@rethrow_different# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
void rethrow_different() {
  try {
    throw_runtime_error();
  } catch (std::runtime_error) {
    throw std::logic_error("transformed"); // Throw a different exception
  }
}

// Function with rethrow that's caught
// CHECK: c:@F@rethrow_caught# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
void rethrow_caught() {
  try {
    try {
      throw_runtime_error();
    } catch (std::runtime_error) {
      throw; // Rethrow
    }
  } catch (std::runtime_error) {
    // Caught the rethrown exception
  }
}

// Function with rethrow of a different exception that's caught
// CHECK: c:@F@rethrow_different_caught# in {{.*}}ast_based_analysis.cpp first declared in
// {{.*}}ast_based_analysis.cpp
void rethrow_different_caught() {
  try {
    try {
      throw_runtime_error();
    } catch (std::runtime_error) {
      throw std::logic_error("transformed"); // Throw a different exception
    }
  } catch (std::logic_error) {
    // Caught the different exception
  }
} 