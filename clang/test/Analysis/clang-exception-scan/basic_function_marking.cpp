// RUN: %gen_compdb %s > %t.json
// RUN: rm -rf %t.output
// RUN: mkdir -p %t.output
// RUN: %clang_exception_scan %t.json %t.output
// RUN: cat %t.output/definite_results.txt | FileCheck %s

#include "Inputs/stdexcept.h"

// CHECK: Functions that could be marked noexcept, but are not:

// CHECK: c:@F@empty# defined in {{.*}}basic_function_marking.cpp first declared in
// {{.*}}basic_function_marking.cpp
void empty() {}

void empty_already_noexcept() noexcept {}

// CHECK: c:@F@return_int# defined in {{.*}}basic_function_marking.cpp first declared in
// {{.*}}basic_function_marking.cpp
int return_int() { return 0; }

int return_int_already_noexcept() noexcept { return 0; }

void throw_runtime_error() { throw std::runtime_error("error"); }

// CHECK: c:@F@catches_all_thrown_exceptions# defined in
// {{.*}}basic_function_marking.cpp first declared in
// {{.*}}basic_function_marking.cpp
void catches_all_thrown_exceptions() {
  try {
    throw_runtime_error();
  } catch (std::runtime_error) {
  }
}

void catches_all_thrown_exceptions_already_noexcept() noexcept {
  try {
    throw_runtime_error();
  } catch (std::runtime_error) {
  }
}

// CHECK: c:@F@catches_all_thrown_exceptions_with_catch_all# defined in
// {{.*}}basic_function_marking.cpp first declared in
// {{.*}}basic_function_marking.cpp
void catches_all_thrown_exceptions_with_catch_all() {
  try {
    throw_runtime_error();
  } catch (...) {
  }
}

void catches_all_thrown_exceptions_with_catch_all_already_noexcept() noexcept {
  try {
    throw_runtime_error();
  } catch (...) {
  }
}

void catches_wrong_exception() {
  try {
    throw_runtime_error();
  } catch (int) {
  }
}

int function_with_unknown_implementation();

// This function is unknown because it calls a function with an unknown
// implementation.
//
// CHECK-NOT: c:@F@calls_unknown_function# defined in {{.*}}basic_function_marking.cpp first declared in
// {{.*}}basic_function_marking.cpp
void calls_unknown_function() { function_with_unknown_implementation(); }

// This function is known to be non-throwing because it calls a builtin
// function that is known to be non-throwing.
//
// CHECK: c:@F@uses_builtin#I# defined in {{.*}}basic_function_marking.cpp first declared in
// {{.*}}basic_function_marking.cpp
int uses_builtin(int x) {
  return __builtin_bswap32(x);
}

// This function is unknown because it calls a function with an unknown
// implementation.
//
// CHECK-NOT: c:@F@uses_builtin_with_unknown#I# defined in {{.*}}basic_function_marking.cpp first declared in
// {{.*}}basic_function_marking.cpp
int uses_builtin_with_unknown(int x) {
  int y = __builtin_bswap32(x);
  function_with_unknown_implementation();
  return y;
}

// Check that the order of different kinds of function calls is not important.
//
// CHECK-NOT: c:@F@order_of_function_calls#I# defined in {{.*}}basic_function_marking.cpp first declared in
// {{.*}}basic_function_marking.cpp
int order_of_function_calls() {
  int a = function_with_unknown_implementation();
  return __builtin_bswap32(a);
}

// Check nested try-catch blocks.
//
// TODO: This is not detected as noexcept. Once fixed, add a check here for:
// c:@F@nested_try_catch# defined in {{.*}}basic_function_marking.cpp first declared in
// {{.*}}basic_function_marking.cpp
void nested_try_catch() {
  try {
    try {
      throw_runtime_error();
    } catch (std::runtime_error) {
    }
  } catch (std::runtime_error) {
  }
}

// Check nested try-catch blocks with rethrow-catch chain
//
// TODO: This is not detected as noexcept. Once fixed, add a check here for:
// c:@F@nested_try_catch_with_rethrow_catch_chain# in {{.*}}basic_function_marking.cpp first declared in
// {{.*}}basic_function_marking.cpp
void nested_try_catch_with_rethrow_catch_chain() {
  try {
    throw_runtime_error();
  } catch (std::runtime_error) {
    throw 42;
  } catch (int) {
  }
}

// Check nested try-catch blocks with rethrows.
//
// TODO: This is not detected as noexcept. Once fixed, add a check here for:
// c:@F@nested_try_catch_with_rethrows# defined in {{.*}}basic_function_marking.cpp first declared in
// {{.*}}basic_function_marking.cpp
void nested_try_catch_with_rethrows() {
  try {
    throw_runtime_error();
  } catch (std::runtime_error) {
    throw;
  }
}