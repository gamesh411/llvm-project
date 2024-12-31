// RUN: %gen_compdb %s > %t.json
// RUN: rm -rf %t.output
// RUN: mkdir -p %t.output
// RUN: %clang_exception_scan %t.json %t.output
// RUN: cat %t.output/definite_results.txt | FileCheck %s

#include "Inputs/stdexcept.h"

// CHECK: Functions that could be marked noexcept, but are not:

// CHECK: c:@F@empty# in {{.*}}basic_function_marking.cpp first declared in
// {{.*}}basic_function_marking.cpp
void empty() {}

void empty_already_noexcept() noexcept {}

// CHECK: c:@F@return_int# in {{.*}}basic_function_marking.cpp first declared in
// {{.*}}basic_function_marking.cpp
int return_int() { return 0; }

int return_int_already_noexcept() noexcept { return 0; }

void throw_runtime_error() { throw std::runtime_error("error"); }

// CHECK: c:@F@catches_all_thrown_exceptions# in
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

// CHECK: c:@F@catches_all_thrown_exceptions_with_catch_all# in
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

void function_with_unknown_implementation();

void calls_unknown_function() { function_with_unknown_implementation(); }
