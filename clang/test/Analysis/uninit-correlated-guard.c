// RUN: %clang_cc1 -Wconditional-uninitialized -fsyntax-only -verify %s

// Test that -Wconditional-uninitialized does not produce false positives
// when a variable's use is guarded by a correlated condition, while still
// warning for genuinely unrelated guards.

int ext_func(int *arr);
int ext_lookup(void);

// Pattern 1: Guard set together with value in the same block.
// The guard is checked before using the value.
// (Reproduces false positive from eps-eth_main_agis_rows.c)
void test_guard_direct(int *data, int count) {
  int restore_if_higher_layer_index = 0;
  int base_hw_port_adr_interface;

  if (ext_func(data) == 1) {
    if (data[0] == count) {
      base_hw_port_adr_interface = ext_lookup();
      restore_if_higher_layer_index = 1;
    }
  }

  // Second check can only set guard BACK to 0, never to 1
  if (restore_if_higher_layer_index != 0) {
    if (ext_func(data) == 1) {
      if (data[0] == count) {
        restore_if_higher_layer_index = 0;
      }
    }
  }

  if (restore_if_higher_layer_index != 0) {
    ext_func(&base_hw_port_adr_interface); // no-warning
  }
}

// Pattern 2: Guard set together with value, then a derived variable
// is used as the actual branch condition.
// (Reproduces false positive from eps-bridge_ps_xfLagTable.c)
int test_guard_transitive(int old_status, int new_status, int mode) {
  int row_status;
  int psData = 0;

  if (old_status != 1 && new_status == 1) {
    psData = 1;
    row_status = 3;
  } else if (new_status == 4) {
    psData = 1;
    row_status = 4;
  } else if (new_status == 1) {
    row_status = new_status;
    psData = 1;
  }

  if (mode == 2)
    return 0;

  int data_storage = 0;
  if (psData == 1) {
    data_storage = 1;
  }

  if (data_storage == 1) {
    return row_status; // no-warning
  }

  return 0;
}

// Negative test: guard and value are NOT correlated (set in different blocks).
// This should still warn.
int test_unrelated_guard(int x, int y) {
  int guard = 0;
  int value; // expected-note {{initialize the variable 'value' to silence this warning}}

  if (x > 0) {
    value = 1;
  }
  if (y > 0) {
    guard = 1;
  }

  if (guard) {
    return value; // expected-warning {{variable 'value' may be uninitialized when used here}}
  }
  return 0;
}
