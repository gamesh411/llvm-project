// RUN: rm -rf %t && mkdir %t
// RUN: %clang_analyze_cc1 -analyzer-checker=core \
// RUN:   -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/on.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-symbols.py %t/on.plist types \
// RUN:   | FileCheck %s

// With the option off there is no trace, so no symbol table either.
// RUN: %clang_analyze_cc1 -analyzer-checker=core \
// RUN:   -analyzer-output=plist-multi-file -o %t/off.plist -verify %s
// RUN: FileCheck %s --check-prefix=OFF --input-file %t/off.plist
// OFF-NOT: constraint_trace
// OFF-NOT: <key>pointer</key>

// An entry says what type its symbol has, without typedefs and qualifiers, and
// whether the analyzer treats it as an address. The dump of a derived symbol
// does not tell either.

typedef __typeof__(sizeof(int)) size_t;
typedef int *IntPtr;
size_t get_size(void);
const int *get_pointer(void);
IntPtr get_typedef_pointer(void);
unsigned get_unsigned(void);
int get(void);

void integer_results(void) {
  int *p = 0;
  if (get_size() == 4 && get_unsigned() == 5)
  // CHECK:     TRACE Dereference of null pointer
  // CHECK-DAG: SYMBOL conj_$[[#]]{{{.*}}} conjured call_result "get_size()" {{.*}} type unsigned long{{$}}
  // CHECK-DAG: SYMBOL conj_$[[#]]{{{.*}}} conjured call_result "get_unsigned()" {{.*}} type unsigned int{{$}}
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

void pointer_results(void) {
  int *p = 0;
  if (get_pointer() != 0 && get_typedef_pointer() != 0 && get())
  // CHECK:     TRACE Dereference of null pointer
  // CHECK-DAG: SYMBOL conj_$[[#]]{{{.*}}} conjured call_result "get_pointer()" {{.*}} type const int * pointer{{$}}
  // CHECK-DAG: SYMBOL conj_$[[#]]{{{.*}}} conjured call_result "get_typedef_pointer()" {{.*}} type int * pointer{{$}}
  // CHECK-DAG: SYMBOL conj_$[[#]]{{{.*}}} conjured call_result "get()" {{.*}} type int{{$}}
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

struct Node { size_t count; struct Node *next; };
void fill_node(struct Node *);

void derived_fields(void) {
  struct Node n = {0, 0};
  int *p = 0;
  fill_node(&n);
  // CHECK:     TRACE Dereference of null pointer
  // CHECK-DAG: SYMBOL derived_$[[#]]{{{.*}},n.count} derived parent {{.*}} region n.count type unsigned long{{$}}
  // CHECK-DAG: SYMBOL derived_$[[#]]{{{.*}},n.next} derived parent {{.*}} region n.next type struct Node * pointer{{$}}
  if (n.count == 3 && n.next != 0)
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}
