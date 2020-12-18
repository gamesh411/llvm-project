// RUN: %clang_analyze_cc1 -fcxx-exceptions -analyzer-checker=core,deadcode.DeadStores,alpha.deadcode.UnreachableCode -verify %s

// Reachable try blocks should not be reported.
void tryBlock(int i) {
  try {
    (void)i;
  }
  catch (...) {}
}

// Empty try blocks are ignored.
void emptyTryBlock(int i) {
  try {} catch (...) {}
}

// First unreachable non-try statement is reported.
void unreachableTryBlock(int i) {
  while(1);
  try {
    (void)i; // expected-warning{{never executed}}
  }
  catch (...) {}
}

// Empty try blocks are ignored.
void unreachableEmptyTryBlock(int i) {
  while(1);
  try {} catch (...) {}
}
