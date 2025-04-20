// RUN: %gen_compdb %s %S/Inputs/ctu_exception_spec_impl.cpp > %t.json
// RUN: rm -rf %t.output
// RUN: mkdir -p %t.output
// RUN: %clang_exception_scan --ast-based --file-selector=%s %t.json %t.output
// RUN: cat %t.output/definite_results.txt | FileCheck %s --check-prefix=CHECK-SINGLE
// RUN: %clang_exception_scan --ast-based %t.json %t.output
// RUN: cat %t.output/definite_results.txt | FileCheck %s --check-prefix=CHECK-MULTI

// CHECK-SINGLE: Functions that could be marked noexcept, but are not:
// CHECK-MULTI: Functions that could be marked noexcept, but are not:

// Function with implementation in another TU that doesn't throw
// In single-TU mode, we can't know if it's safe
// CHECK-SINGLE-NOT: c:@F@safe_function# defined in {{.*}}ctu_exception_spec_impl.cpp
// In multi-TU mode, we can see it's safe
// CHECK-MULTI: c:@F@safe_function# defined in {{.*}}ctu_exception_spec_impl.cpp first declared in {{.*}}ctu_exception_spec_impl.cpp
void safe_function();

// Function with implementation in another TU that does throw
// In both modes, we should not mark it as safe
// CHECK-SINGLE-NOT: c:@F@throwing_function# defined in {{.*}}ctu_exception_spec_impl.cpp
// CHECK-MULTI-NOT: c:@F@throwing_function# defined in {{.*}}ctu_exception_spec_impl.cpp
void throwing_function();

// Function that calls safe_function
// In both modes, we don't mark it as noexcept since we only mark functions that are directly noexcept
// CHECK-SINGLE-NOT: c:@F@calls_safe# defined in {{.*}}ctu_exception_spec.cpp
// CHECK-MULTI-NOT: c:@F@calls_safe# defined in {{.*}}ctu_exception_spec.cpp
void calls_safe() {
    safe_function();
}

// Function that calls throwing_function
// In both modes, we should not mark it as safe
// CHECK-SINGLE-NOT: c:@F@calls_throwing# defined in {{.*}}ctu_exception_spec.cpp
// CHECK-MULTI-NOT: c:@F@calls_throwing# defined in {{.*}}ctu_exception_spec.cpp
void calls_throwing() {
    throwing_function();
}

// Local function that is safe
// Should be marked safe in both modes since it's directly noexcept
// CHECK-SINGLE: c:@F@local_safe# defined in {{.*}}ctu_exception_spec.cpp first declared in {{.*}}ctu_exception_spec.cpp
// CHECK-MULTI: c:@F@local_safe# defined in {{.*}}ctu_exception_spec.cpp first declared in {{.*}}ctu_exception_spec.cpp
void local_safe() {
    // Does nothing, can be noexcept
} 