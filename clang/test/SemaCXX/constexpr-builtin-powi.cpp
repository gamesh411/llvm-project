// RUN: %clang_cc1 -std=c++20 -verify %s

// Test that __builtin_powi, __builtin_powif, and __builtin_powil can be used in constexpr contexts

constexpr double test_powi_1() {
  return __builtin_powi(2.0, 3);
}

constexpr double test_powi_2() {
  return __builtin_powi(2.0, -3);
}

constexpr double test_powi_zero_exp() {
  return __builtin_powi(2.0, 0);
}

constexpr double test_powi_zero_base_pos_exp() {
  return __builtin_powi(0.0, 3);
}

constexpr double test_powi_zero_base_neg_exp() {
  return __builtin_powi(0.0, -3);
}

constexpr double test_powi_zero_base_zero_exp() {
  return __builtin_powi(0.0, 0);
}

constexpr float test_powif_1() {
  return __builtin_powif(2.0f, 3);
}

constexpr float test_powif_2() {
  return __builtin_powif(2.0f, -3);
}

constexpr long double test_powil_1() {
  return __builtin_powil(2.0L, 3);
}

constexpr long double test_powil_2() {
  return __builtin_powil(2.0L, -3);
}

// Test using the builtins in constexpr variables
constexpr double d1 = __builtin_powi(2.0, 3);
constexpr double d2 = __builtin_powi(2.0, -3);
constexpr double d3 = __builtin_powi(0.0, 0);

constexpr float f1 = __builtin_powif(2.0f, 3);
constexpr float f2 = __builtin_powif(2.0f, -3);

constexpr long double ld1 = __builtin_powil(2.0L, 3);
constexpr long double ld2 = __builtin_powil(2.0L, -3);

// Test using the builtins in constexpr if statements
constexpr bool b1 = __builtin_powi(2.0, 3) == 8.0;
constexpr bool b2 = __builtin_powif(2.0f, 3) == 8.0f;
constexpr bool b3 = __builtin_powil(2.0L, 3) == 8.0L;

// Test in more complex constexpr functions
constexpr double complex_test() {
  double result = 0.0;
  for (int i = 0; i < 5; ++i) {
    result += __builtin_powi(2.0, i);
  }
  return result;
}

constexpr double expected_complex = 1.0 + 2.0 + 4.0 + 8.0 + 16.0;
static_assert(complex_test() == expected_complex, "Complex test failed");

// Test with constexpr variables as arguments
constexpr int exp = 3;
constexpr double base = 2.0;
constexpr double computed = __builtin_powi(base, exp);
constexpr double expected = 8.0;
static_assert(computed == expected, "Computation with constexpr variables failed");

int main() {
  static_assert(test_powi_1() == 8.0, "test_powi_1 failed");
  static_assert(test_powi_2() == 0.125, "test_powi_2 failed");
  static_assert(test_powi_zero_exp() == 1.0, "test_powi_zero_exp failed");
  static_assert(test_powi_zero_base_pos_exp() == 0.0, "test_powi_zero_base_pos_exp failed");
  static_assert(test_powi_zero_base_zero_exp() == 1.0, "test_powi_zero_base_zero_exp failed");
  
  static_assert(test_powif_1() == 8.0f, "test_powif_1 failed");
  static_assert(test_powif_2() == 0.125f, "test_powif_2 failed");
  
  static_assert(test_powil_1() == 8.0L, "test_powil_1 failed");
  static_assert(test_powil_2() == 0.125L, "test_powil_2 failed");
  
  return 0;
}
