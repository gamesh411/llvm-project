// RUN: %clang_analyze_cc1 \
// RUN:     -analyzer-checker=core \
// RUN:     -analyzer-checker=unix.cstring \
// RUN:     -analyzer-checker=unix.Malloc \
// RUN:     -analyzer-checker=debug.ExprInspection \
// RUN:     -analyzer-config eagerly-assume=false \
// RUN:     -analyzer-checker=alpha.unix.cstring.UninitializedRead \
// RUN:     -verify %s

// This test verifies that UninitializedRead produces warnings even when
// OutOfBounds is disabled. Previously, CheckBufferAccess would early-return
// before reaching checkInit() when OutOfBounds was disabled, suppressing
// UninitializedRead as a side effect.

#include "Inputs/system-header-simulator-cxx.h"
#include "Inputs/system-header-simulator-for-malloc.h"

void memmove_uninit_without_outofbound() {
  int src[4];
  int dst[4];
  memmove(dst, src, sizeof(src)); // expected-warning{{The first element of the 2nd argument is undefined}}
                                  // expected-note@-1{{Other elements might also be undefined}}
}
