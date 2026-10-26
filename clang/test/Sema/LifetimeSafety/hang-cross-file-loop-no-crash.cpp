// Regression test: live-origins analysis must not hang when the record is declared in a separate file from the method body.
// RUN: rm -rf %t
// RUN: split-file %s %t
// RUN: %clang_cc1 -fsyntax-only -Wlifetime-safety-use-after-scope -I%t %t/test.cpp

//--- header.h
#pragma once
typedef unsigned char *P;
struct S {
  int n;
  P a, b;
  void r();
  int m();
};

//--- test.cpp
#include "header.h"
int S::m() {
  for (; n;) {
    int t;
    if (t) {
      if (a)
        a = b;
      continue;
    }
    r();
  }
  return 0;
}
