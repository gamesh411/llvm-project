// RUN: %gen_compdb %s %S/Inputs/ctu_exception_spec_impl.cpp > %t.json
// RUN: rm -rf %t.output
// RUN: mkdir -p %t.output
// RUN: mkdir -p %t.output/MULTI
// UN: %clang_exception_scan --file-selector=%s %t.json %t.output
// UN: cat %t.output/definite_results.txt | FileCheck %s --check-prefix=CHECK-SINGLE
// RUN: %clang_exception_scan %t.json %t.output/MULTI
// RUN: cat %t.output/MULTI/definite_results.txt | FileCheck %s --check-prefix=CHECK-MULTI
// RUN: cat %t.output/MULTI/analysis_stats.txt | FileCheck %s --check-prefix=CHECK-STATS

// CHECK-SINGLE: Functions that could be marked noexcept, but are not:
// CHECK-MULTI: Functions that could be marked noexcept, but are not:

// Function with implementation in another TU that doesn't throw
// In single-TU mode, we can't know if it's safe
// CHECK-SINGLE-NOT: c:@F@safe_function# defined in {{.*}}ctu_exception_spec_impl.cpp
// In multi-TU mode, we can see it's safe
// CHECK-MULTI: c:@F@safe_function# defined in {{.*}}ctu_exception_spec_impl.cpp
void safe_function();

// Function with implementation in another TU that does throw
// In both modes, we should not mark it as safe
// CHECK-SINGLE-NOT: c:@F@throwing_function#
// CHECK-MULTI-NOT: c:@F@throwing_function#
void throwing_function();

// Function that calls safe_function
// In both modes, we don't mark it as noexcept since we only mark functions that are directly noexcept
// CHECK-SINGLE-NOT: c:@F@calls_safe#
// CHECK-MULTI: c:@F@calls_safe# defined in {{.*}}ctu_exception_spec.cpp
void calls_safe() {
    safe_function();
}

// Function that calls throwing_function
// In both modes, we should not mark it as safe
// CHECK-SINGLE-NOT: c:@F@calls_throwing#
// CHECK-MULTI-NOT: c:@F@calls_throwing#
void calls_throwing() {
    throwing_function();
}

// Local function that is safe
// Should be marked safe in both modes since it's directly noexcept
// CHECK-SINGLE: c:@F@local_safe# defined in {{.*}}ctu_exception_spec.cpp
// CHECK-MULTI: c:@F@local_safe# defined in {{.*}}ctu_exception_spec.cpp
void local_safe() {
    // Does nothing, can be noexcept
} 

void test_throw_in_try() {
    try {
        throwing_function();
    } catch (...) {
        throw 1;
    }
}

void test_immediately_invoked_lambda() {
    try {
        []{
            throw 1;
        }();
    } catch (...) {
        throw 2;
    }
}

void test_inner_class_definition() {
    struct Inner {
        void f() {
            throw 1;
        }
    };

    try {
        Inner inner;
        inner.f();
    } catch (...) {
        throw;
    }
}

// CHECK-STATS: Total non-system-header function definitions: 9
// CHECK-STATS: Total non-system-header try blocks: 3
// CHECK-STATS: Total non-system-header catch handlers: 3
// CHECK-STATS: Total non-system-header throw expressions: 7
// CHECK-STATS: Total non-system-header calls potentially within try blocks: 3

// Explanation for stats checking:
// Func Defs: safe_function, throwing_function, calls_safe, calls_throwing, local_safe, test_throw_in_try, test_immediately_invoked_lambda, the lambda's operator(), test_inner_class_definition (9)
// Try Blocks: 1 (in test_throw_in_try) + 1 (in test_immediately_invoked_lambda) + 1 (in test_inner_class_definition) = 3
// Catch Handlers: 1 (in test_throw_in_try) + 1 (in test_immediately_invoked_lambda) + 1 (in test_inner_class_definition) = 3
// Throw Expressions: 1 (in throwing_function implementation) + 1 (in test_throw_in_try) + 1 (in test_immediately_invoked_lambda) + 1 (in test_inner_class_definition) = 4
// Calls in Try: 1 (throwing_function() called within try in test_throw_in_try) + 1 (lambda called within try in test_immediately_invoked_lambda) + 1 (inner.f() called within try in test_inner_class_definition) = 3
