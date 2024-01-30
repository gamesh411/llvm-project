// RUN: %clang_analyze_cc1 -analyzer-checker=experimental.LTLFormulaChecker -verify %s

void test(void) {
  (void)0;
} // expected-warning{{LTL formula checker}}
