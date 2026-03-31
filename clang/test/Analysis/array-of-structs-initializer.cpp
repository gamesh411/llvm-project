// RUN: %clang_analyze_cc1 -xc -analyzer-checker=core,debug.ExprInspection -verify=expected,c %s
// RUN: %clang_analyze_cc1 -xc++ -DCPP -std=c++14 -analyzer-checker=core,debug.ExprInspection -verify=expected,cpp %s

void clang_analyzer_value(int);

struct CStruct {
  int a;
};

struct CStruct nonconst_c_struct_array[1] = {
  {11},
};

void use_nonconst_struct_array_c(void) {
  clang_analyzer_value(nonconst_c_struct_array->a); // expected-warning {{32s:{ [-2147483648, 2147483647] }}}
}

const struct CStruct const_c_struct_array[1] = { {22} };

void use_const_struct_array_c(void) {
  clang_analyzer_value(const_c_struct_array->a); // expected-warning {{22}}
}

#ifdef CPP
struct CPPStruct {
  int a = 33;
};

CPPStruct nonconst_cpp_struct_array[1] = {};
const CPPStruct const_cpp_struct_array[1] = {};

struct CPPStructWithUserCtor {
  int a = 44;
  CPPStructWithUserCtor(): a(55) {}
};

CPPStructWithUserCtor nonconst_cpp_struct_wctor_array[1] = {};

void use_nonconst_struct_array_cpp(void) {
  clang_analyzer_value(nonconst_cpp_struct_array->a); // cpp-warning {{32s:{ [-2147483648, 2147483647] }}}
}

const CPPStructWithUserCtor const_cpp_struct_wctor_array[1] = {};
#endif

int main(int argc, char **argv) {
  // FIXME: In C++ mode, IsMainAnalysis is false because global constructors
  // may run before main(), so the initializer for non-const globals are not
  // considered. In C mode this correctly resolves to 11.
  clang_analyzer_value(nonconst_c_struct_array->a); // c-warning {{11}} cpp-warning {{32s:{ [-2147483648, 2147483647] }}}

#ifdef CPP
  // FIXME: Once we model default member initialization, this should be 33.
  clang_analyzer_value(const_cpp_struct_array->a); // cpp-warning {{32s:{ [-2147483648, 2147483647] }}}

  // FIXME: Even if we modeled default member initialization, because of C++
  // mode, initializers of non-const globals are not considered. If they were,
  // this should be 33.
  clang_analyzer_value(nonconst_cpp_struct_array->a); // cpp-warning {{32s:{ [-2147483648, 2147483647] }}}

  // FIXME: Once we model constructors for global arrays, this should be 55.
  clang_analyzer_value(const_cpp_struct_wctor_array->a); // cpp-warning {{32s:{ [-2147483648, 2147483647] }}}

  // FIXME: Even if we modeled default member initialization, because of C++
  // mode, non-const globals' initializers are not considered. If they were,
  // the ctor's initializer list has precedence over the default member
  // initializer, so the correct value should be 55.
  clang_analyzer_value(nonconst_cpp_struct_wctor_array->a); // cpp-warning {{32s:{ [-2147483648, 2147483647] }}}
#endif
}

