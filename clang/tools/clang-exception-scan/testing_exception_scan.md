# Testing Guide for clang-exception-scan

This document describes how to test the clang-exception-scan tool using LLVM's integrated test infrastructure.

## Test Infrastructure

The tests for clang-exception-scan use LLVM's lit (LLVM Integrated Tester) and FileCheck infrastructure. Tests are located in:

```
clang/test/clang-exception-scan/
```

## Test Types

1. **Basic Functionality Tests**
   - Exception throwing detection
   - Exception catching detection
   - Try block detection
   - Function call detection

2. **Cross-Translation Unit Tests**
   - Exception propagation across translation units
   - Function call graph analysis

## Test File Structure

Each test file should:
1. Have a `.cpp` extension
2. Include RUN and CHECK lines
3. Test a specific functionality
4. Have clear comments explaining the test case

Example:
```cpp
// RUN: %clang -cc1 -analyze -analyzer-checker=core %s -verify

void throws() {
  throw 42;  // CHECK: throws:4:3: note: throw detected
}

void catches() {
  try {      // CHECK: catches:8:3: note: try block detected
    throws();
  } catch (int) {  // CHECK: catches:10:3: note: catch(int) detected
  }
}
```

## Test Categories

### 1. Basic Exception Tests
- `basic-throw.cpp`: Test basic throw statement detection
- `basic-catch.cpp`: Test basic catch clause detection
- `basic-try.cpp`: Test basic try block detection
- `nested-try.cpp`: Test nested try-catch blocks
- `rethrow.cpp`: Test exception rethrow detection

### 2. Function Call Tests
- `direct-calls.cpp`: Test direct function call detection
- `virtual-calls.cpp`: Test virtual function call detection
- `ctor-calls.cpp`: Test constructor call detection

### 3. Cross-TU Tests
- `cross-tu-throw.cpp` and `cross-tu-catch.cpp`: Test exception flow across translation units
- `cross-tu-calls.cpp`: Test function call detection across translation units

## Running Tests

1. Build the test suite:
```bash
ninja check-clang-exception-scan
```

2. Run individual tests:
```bash
llvm-lit clang/test/clang-exception-scan/basic-throw.cpp
```

## Adding New Tests

1. Create a new `.cpp` file in `clang/test/clang-exception-scan/`
2. Add RUN line specifying how to run clang-exception-scan
3. Add CHECK lines to verify output
4. Add test to CMakeLists.txt if necessary

Example new test:
```cpp
// RUN: %clang_exception_scan %s | FileCheck %s

struct S {
  ~S() { throw 42; }  // CHECK: destructor-throw:4:11: note: throw in destructor detected
};

void test() {
  S s;  // CHECK: test:8:5: note: potential throw from destructor
}
```

## Test Infrastructure Setup

1. Create test directory:
```bash
mkdir -p clang/test/clang-exception-scan
```

2. Add lit configuration:
```bash
# clang/test/clang-exception-scan/lit.local.cfg
config.substitutions.append(('%clang_exception_scan', 'clang-exception-scan'))
```

3. Update CMakeLists.txt:
```cmake
# clang/test/CMakeLists.txt
add_subdirectory(clang-exception-scan)
```

## Common Test Patterns

1. **Testing Exception Flow**
```cpp
// RUN: %clang_exception_scan %s | FileCheck %s

void f() { throw 1; }     // CHECK: note: throw detected
void g() { f(); }         // CHECK: note: potential throw from f()
void h() { 
  try { g(); }           // CHECK: note: try block may catch throw from f()
  catch(int) { }
}
```

2. **Testing Complex Exception Paths**
```cpp
// RUN: %clang_exception_scan %s | FileCheck %s

struct Base {
  virtual ~Base() {}
};
struct Derived : Base {
  ~Derived() { throw 1; }  // CHECK: note: throw in destructor
};
void test() {
  Base* b = new Derived;
  delete b;               // CHECK: note: potential throw from Derived destructor
}
```

## Best Practices

1. Each test should focus on one specific feature
2. Use meaningful variable and function names
3. Add comments explaining complex test cases
4. Verify both positive and negative cases
5. Test edge cases and error conditions

## Debugging Tests

1. Use the -v flag for verbose output:
```bash
llvm-lit -v clang/test/clang-exception-scan/test.cpp
```

2. Use XFAIL for known failures:
```cpp
// XFAIL: *
// RUN: %clang_exception_scan %s
```

3. Use REQUIRES for platform-specific tests:
```cpp
// REQUIRES: x86-registered-target
// RUN: %clang_exception_scan %s
``` 