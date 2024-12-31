// RUN: %gen_compdb -I%S %s > %t.json
// RUN: %clang_exception_scan %t.json | FileCheck %s

void f() {
  throw 42;  // CHECK: Loading compilation database {{.*}}
             // CHECK: Function:
             // CHECK: uncaught throws:
             // CHECK: - int
}

void g() {
  try {      // CHECK: Function:
             // CHECK: tries:
             // CHECK: - {{.*}}
    f();     // CHECK: calls:
             // CHECK: - f
  } catch (int) {  // CHECK: catches:
                   // CHECK: - int
  }
} 