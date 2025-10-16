// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.dsl.EmbeddedDSLMonitor \
// RUN:   -verify %s

void *malloc(unsigned long);
void free(void *);

// Helper function for error handling tests
int some_condition(void) {
  return 1;
}

void ok_exactly_once() {
  void *p = malloc(16); // no-note
  if (!p) // expected-note{{Assuming 'p' is null}} // expected-note{{Taking true branch}}
    return; // no-warning
  free(p); // no-warning
} // expected-warning{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}} 

void leak_missing_free() {
  void *p = malloc(32); // no-note
  return;  // no-warning
} // expected-warning{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}

void double_free(int a) {
  void *p = malloc(8); // no-note
  free(p); // no-warning
  free(p); // expected-warning{{resource destroyed twice (violates exactly-once) (internal symbol: sym_2)}} // expected-note{{resource destroyed twice (violates exactly-once) (internal symbol: sym_2)}}
}

#if 0

//===----------------------------------------------------------------------===//
// Complex Control Flow Tests
//===----------------------------------------------------------------------===//

void complex_control_flow_leak(int condition) {
  void *p = malloc(64); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  if (condition > 0) { // expected-note{{Assuming 'condition' is > 0}} // expected-note{{Taking true branch}}
    if (condition > 10) { // expected-note{{Assuming 'condition' is <= 10}} // expected-note{{Taking false branch}}
      free(p);
      return; // no-warning
    } else {
      return; // expected-warning{{resource not destroyed (violates exactly-once)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}
    }
  } else {
    free(p);
  }
}

void nested_loops_with_leak(int n) {
  void *p = malloc(32); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  for (int i = 0; i < n; i++) { // expected-note{{Assuming 'i' is >= 'n'}} // expected-note{{Loop condition is false. Execution jumps to the end of the function}}
    for (int j = 0; j < n; j++) {
      if (i == j) {
        free(p);
        return; // no-warning
      }
    }
  }
  // p is not freed if loops don't find i == j
  return; // expected-warning{{resource not destroyed (violates exactly-once)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}
}

void switch_statement_leak(int choice) {
  void *p = malloc(16); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  switch (choice) { // expected-note{{Control jumps to 'case 2:'  at line 68}} // expected-note{{Control jumps to the 'default' case at line 73}}
    case 1:
      free(p);
      break;
    case 2:
      return; // expected-warning{{resource not destroyed (violates exactly-once)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}
    case 3:
      free(p);
      break;
    default:
      return; // expected-warning{{resource not destroyed (violates exactly-once)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}
  }
}

void multiple_allocations_ok() {
  void *p1 = malloc(16); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  void *p2 = malloc(32); // expected-note{{symbol "x" is bound here (internal symbol: sym_5)}}
  void *p3 = malloc(8); // expected-note{{symbol "x" is bound here (internal symbol: sym_8)}}
  
  free(p1);
  free(p2);
  free(p3); // no-warning
}

void multiple_allocations_mixed() {
  void *p1 = malloc(16); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  void *p2 = malloc(32); // expected-note{{symbol "x" is bound here (internal symbol: sym_5)}}
  
  free(p1); // expected-warning{{resource not destroyed (violates exactly-once)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_5)}}
  // p2 is not freed
  return;
}

//===----------------------------------------------------------------------===//
// Function Call Tests
//===----------------------------------------------------------------------===//

void helper_free(void *ptr) {
  free(ptr);
}

void helper_alloc_and_free() {
  void *p = malloc(24); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  helper_free(p); // no-warning
}

void helper_alloc_no_free() {
  void *p = malloc(24); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  // helper_free not called
  return; // expected-warning{{resource not destroyed (violates exactly-once)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}
}

void *helper_alloc() {
  return malloc(40); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
}

void helper_alloc_caller() {
  void *p = helper_alloc();
  free(p); // no-warning
}

void helper_alloc_caller_leak() {
  void *p = helper_alloc(); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  // p is not freed
  return; // expected-warning{{resource not destroyed (violates exactly-once)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}
}

//===----------------------------------------------------------------------===//
// Complex Function Interaction Tests
//===----------------------------------------------------------------------===//

void complex_function_chain_ok() {
  void *p1 = malloc(16); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  void *p2 = malloc(32); // expected-note{{symbol "x" is bound here (internal symbol: sym_5)}}
  
  if (p1 && p2) { // expected-note{{Assuming 'p1' is null}} // expected-note{{Left side of '&&' is false}} // expected-note{{Assuming 'p1' is non-null}} // expected-note{{Left side of '&&' is true}} // expected-note{{Assuming 'p2' is null}} // expected-note{{Taking false branch}}
    free(p1);
    free(p2);
    return; // no-warning
  }
  
  // Cleanup on error
  if (p1) free(p1); // expected-note{{'p1' is null}} // expected-note{{Taking false branch}} // expected-note{{'p1' is non-null}} // expected-note{{Taking true branch}}
  if (p2) free(p2); // expected-warning{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}} // expected-note{{'p2' is null}} // expected-note{{Taking false branch}}
} // expected-warning{{resource not destroyed (violates exactly-once) (internal symbol: sym_5)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_5)}}

void complex_function_chain_leak() {
  void *p1 = malloc(16); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  void *p2 = malloc(32); // expected-note{{symbol "x" is bound here (internal symbol: sym_5)}}
  
  if (p1 && p2) { // expected-note{{Assuming 'p1' is non-null}} // expected-note{{Left side of '&&' is true}} // expected-note{{Assuming 'p2' is non-null}} // expected-note{{Taking true branch}} // expected-note{{Assuming 'p1' is null}} // expected-note{{Left side of '&&' is false}} // expected-note{{Assuming 'p1' is non-null}} // expected-note{{Left side of '&&' is true}} // expected-note{{Assuming 'p2' is null}} // expected-note{{Taking false branch}}
    free(p1); // expected-warning{{resource not destroyed (violates exactly-once) (internal symbol: sym_5)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_5)}}
    // p2 is not freed
    return;
  }
  
  // Cleanup on error
  if (p1) free(p1); // expected-note{{'p1' is null}} // expected-note{{Taking false branch}} // expected-note{{'p1' is non-null}} // expected-note{{Taking true branch}}
  if (p2) free(p2); // expected-warning{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}} // expected-note{{'p2' is null}} // expected-note{{Taking false branch}}
} // expected-warning{{resource not destroyed (violates exactly-once) (internal symbol: sym_5)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_5)}}

void recursive_cleanup(int depth) {
  void *p = malloc(16); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  
  if (depth > 0) {
    recursive_cleanup(depth - 1);
  }
  
  free(p); // no-warning
}

void recursive_cleanup_leak(int depth) {
  void *p = malloc(16); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  
  if (depth > 0) { // expected-note{{Assuming 'depth' is > 0}} // expected-note{{Taking true branch}}
    recursive_cleanup_leak(depth - 1); // expected-warning{{resource not destroyed (violates exactly-once)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}
    return;
  }
  
  free(p);
}

//===----------------------------------------------------------------------===//
// Edge Cases and Error Handling
//===----------------------------------------------------------------------===//

void error_handling_ok() {
  void *p = malloc(16); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  if (!p) { // expected-note{{Assuming 'p' is null}} // expected-note{{Taking true branch}}
    return; // no-warning
  } // expected-warning{{resource not destroyed (violates exactly-once)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}
  
  // Do some work
  if (some_condition()) {
    free(p);
    return; // no-warning
  }
  
  free(p);
}

void error_handling_leak() {
  void *p = malloc(16); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  if (!p) { // expected-note{{Assuming 'p' is null}} // expected-note{{Taking true branch}} // expected-note{{Assuming 'p' is non-null}} // expected-note{{Taking false branch}}
    return; // expected-warning{{resource not destroyed (violates exactly-once)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}
  }
  
  // Do some work
  if (some_condition()) { // expected-note{{Taking true branch}}
    return; // no-warning
  } // expected-warning{{resource not destroyed (violates exactly-once)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}
  
  free(p);
}

void early_return_patterns(int flag) {
  void *p = malloc(20); // expected-note{{symbol "x" is bound here (internal symbol: sym_2)}}
  
  if (flag == 1) { // expected-note{{Assuming 'flag' is not equal to 1}} // expected-note{{Taking false branch}}
    free(p);
    return; // no-warning
  }
  
  if (flag == 2) { // expected-note{{Assuming 'flag' is equal to 2}} // expected-note{{Taking true branch}}
    return; // expected-warning{{resource not destroyed (violates exactly-once)}} // expected-note{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}
  }
  
  if (flag == 3) {
    free(p);
    return; // no-warning
  }
  
  // Default case
  free(p);
}

#endif