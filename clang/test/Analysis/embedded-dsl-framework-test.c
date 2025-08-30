// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.unix.EmbeddedDSLMonitor %s

// Test file for verifying the embedded DSL framework functionality
// This test ensures that the framework can handle various scenarios

// Declare malloc and free functions
void *malloc(unsigned long size);
void free(void *ptr);
#define NULL ((void*)0)

// Test 1: Basic malloc/free pattern - should pass
void test_basic_malloc_free() {
  void *p = malloc(32);
  if (p) {
    free(p);
  }
} // no-warning

// Test 2: Memory leak - should trigger warning
void test_memory_leak() {
  void *p = malloc(32);
  // Missing free(p) - should trigger memory leak warning
} // expected-warning{{allocated memory is not freed (violates exactly-once)}}

// Test 3: Double free - should trigger warning
void test_double_free() {
  void *p = malloc(32);
  if (p) {
    free(p);
    free(p); // expected-warning{{Double free: memory freed multiple times}}
  }
}

// Test 4: Null check before free - should pass
void test_null_check_free() {
  void *p = malloc(32);
  if (p != NULL) {
    free(p);
  }
} // no-warning

// Test 5: Multiple allocations and frees - should pass
void test_multiple_allocations() {
  void *p1 = malloc(32);
  void *p2 = malloc(64);
  
  if (p1 && p2) {
    free(p1);
    free(p2);
  }
} // no-warning

// Test 6: Conditional allocation and free - should pass
void test_conditional_allocation(int condition) {
  void *p = NULL;
  if (condition) {
    p = malloc(32);
  }
  
  if (p) {
    free(p);
  }
} // no-warning

// Test 7: Early return with leak - should trigger warning
void test_early_return_leak(int condition) {
  void *p = malloc(32);
  if (condition) {
    return; // expected-warning{{allocated memory is not freed (violates exactly-once)}}
  }
  free(p);
}

// Test 8: Nested allocation - should pass
void test_nested_allocation() {
  void *outer = malloc(128);
  if (outer) {
    void *inner = malloc(64);
    if (inner) {
      free(inner);
    }
    free(outer);
  }
} // no-warning

// Test 9: Complex control flow - should pass
void test_complex_control_flow(int a, int b) {
  void *p = malloc(32);
  if (p) {
    if (a > 0) {
      if (b > 0) {
        free(p);
      } else {
        free(p);
      }
    } else {
      free(p);
    }
  }
} // no-warning

// Test 10: Function call with allocation - should pass
void helper_function(void **ptr) {
  *ptr = malloc(32);
}

void test_function_call_allocation() {
  void *p = NULL;
  helper_function(&p);
  if (p) {
    free(p);
  }
} // no-warning
