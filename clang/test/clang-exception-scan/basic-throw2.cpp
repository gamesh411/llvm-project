// RUN: %gen_compdb -I%S %s > %t.json
// RUN: %clang_exception_scan %t.json | FileCheck %s

// CHECK: Loading compilation database {{.*}}
void f2() {
  throw 42;
}
// CHECK: Function 'f' throws exceptions:
// CHECK-NEXT: {{.*}}'int'

void g2() {
  try {
    f2();
  } catch (int) {}
} 
// CHECK: Function 'g' does not throw exceptions.

void unknown2();

void h2() {
  unknown2();
}
// CHECK: Function 'h' is unknown to throw exceptions.
