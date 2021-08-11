// RUN: %check_clang_tidy %s cert-smart-pointer-deleter %t -- --fix-notes

#include "Inputs/modernize-smart-ptr/shared_ptr.h"
#include "Inputs/modernize-smart-ptr/unique_ptr.h"

struct ObjectDeleter {
  template <typename T>
  void operator()(const T *ptr) const noexcept {
    delete ptr;
  }
};

struct ArrayDeleter {
  template <typename T>
  void operator()(const T *ptr) const noexcept {
    delete[] ptr;
  }
};

auto ObjectDeleterLambda = [](const auto *Ptr) noexcept { delete Ptr; };
auto ArrayDeleterLambda = [](const auto *Ptr) noexcept { delete[] Ptr; };

void mismatched_deleter_unique_ptr() {
  std::unique_ptr<int> Ptr1{new int[10]};
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::unique_ptr with base type int has deleter for type int[] [cert-smart-pointer-deleter]

  std::unique_ptr<int> Ptr2;
  Ptr2.reset(new int[10]);
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::unique_ptr with base type int has deleter for type int[] [cert-smart-pointer-deleter]

  std::unique_ptr<int> Ptr3 = std::make_unique<int[]>(10);
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::unique_ptr with base type int has deleter for type int[] [cert-smart-pointer-deleter]

  std::unique_ptr<int[]> Ptr4{new int};
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::unique_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]

  std::unique_ptr<int[]> Ptr5;
  Ptr5.reset(new int);
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::unique_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]

  std::unique_ptr<int[]> Ptr6 = std::make_unique<int>();
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::unique_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]
}

void mismatched_deleter_shared_ptr() {
  std::shared_ptr<int> Ptr1{new int[10]};
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::shared_ptr with base type int has deleter for type int[] [cert-smart-pointer-deleter]

  std::shared_ptr<int> Ptr2;
  Ptr2.reset(new int[10]);
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::shared_ptr with base type int has deleter for type int[] [cert-smart-pointer-deleter]

  std::shared_ptr<int> Ptr3 = std::make_unique<int[]>(10);
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::shared_ptr with base type int has deleter for type int[] [cert-smart-pointer-deleter]

  std::shared_ptr<int[]> Ptr4{new int};
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::shared_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]

  std::shared_ptr<int[]> Ptr5;
  Ptr5.reset(new int);
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::shared_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]

  std::shared_ptr<int[]> Ptr6 = std::make_unique<int>();
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::shared_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]
}

template <typename SmartPtrTy>
void mismatched_deleter_in_template() {
  SmartPtrTy<int> Ptr1{new int[10]};
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::unique_ptr with base type int has deleter for type int[] [cert-smart-pointer-deleter]
  // CHECK-MESSAGES: :[[@LINE-2]]:6: warning: std::shared_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]

  SmartPtrTy<int> Ptr2;
  Ptr2.reset({new int[10]});
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::unique_ptr with base type int has deleter for type int[] [cert-smart-pointer-deleter]
  // CHECK-MESSAGES: :[[@LINE-2]]:6: warning: std::shared_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]

  SmartPtrTy<int> Ptr3 = std::make_unique<int[]>(10);
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::unique_ptr with base type int has deleter for type int[] [cert-smart-pointer-deleter]
  // CHECK-MESSAGES: :[[@LINE-2]]:6: warning: std::shared_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]

  SmartPtrTy<int[]> Ptr4{new int};
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::unique_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]
  // CHECK-MESSAGES: :[[@LINE-2]]:6: warning: std::shared_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]

  SmartPtrTy<int[]> Ptr5;
  Ptr5.reset(new int);
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::unique_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]
  // CHECK-MESSAGES: :[[@LINE-2]]:6: warning: std::shared_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]

  SmartPtrTy<int[]> Ptr6 = std::make_unique<int>();
  // CHECK-MESSAGES: :[[@LINE-1]]:6: warning: std::unique_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]
  // CHECK-MESSAGES: :[[@LINE-2]]:6: warning: std::shared_ptr with base type int[] has deleter for type int [cert-smart-pointer-deleter]
}

void mismatched_smart_pointer_in_template() {
  mismatched_deleter_in_template<std::unique_ptr<int>>();
  mismatched_deleter_in_template<std::shared_ptr<int>>();
}

// Negative test cases.

void matching_deleter_unique_ptr() {
  std::unique_ptr<int> Ptr1{new int};

  std::unique_ptr<int> Ptr2;
  Ptr2.reset(new int);

  std::unique_ptr<int> Ptr3 = std::make_unique<int>();

  std::unique_ptr<int[]> Ptr4{new int[10]};

  std::unique_ptr<int[]> Ptr5;
  Ptr5.reset(new int[10]);

  std::unique_ptr<int[]> Ptr6 = std::make_unique<int[]>(10);

  // Custom deleter cases.

  std::unique_ptr<int, ObjectDeleter> Ptr7{new int};

  std::unique_ptr<int, ArrayDeleter> Ptr8{new int[]};

  std::unique_ptr<int[], ObjectDeleter> Ptr9{new int};

  std::unique_ptr<int[], ArrayDeleter> Ptr10{new int[]};
}

void matching_deleter_shared_ptr() {
  std::shared_ptr<int> Ptr1{new int};

  std::shared_ptr<int> Ptr2;
  Ptr2.reset(new int);

  std::shared_ptr<int> Ptr3 = std::make_shared<int>();

  std::shared_ptr<int[]> Ptr4{new int[10]};

  std::shared_ptr<int[]> Ptr5;
  Ptr5.reset(new int[10]);

  std::shared_ptr<int[]> Ptr6 = std::make_shared<int[]>(10);

  // Custom deleter cases.

  std::shared_ptr<int> Ptr7{new int, ObjectDeleterLambda};

  std::shared_ptr<int> Ptr8{new int, ObjectDeleter{}};

  std::shared_ptr<int> Ptr7{new int[], ArrayDeleterLambda};

  std::shared_ptr<int> Ptr8{new int[], ArrayDeleter{}};

  std::shared_ptr<int[]> Ptr9{new int, ObjectDeleterLambda};

  std::shared_ptr<int[]> Ptr10{new int, ObjectDeleter{}};

  std::shared_ptr<int[]> Ptr11{new int[], ArrayDeleterLambda};

  std::shared_ptr<int[]> Ptr12{new int[], ArrayDeleter{}};
}
