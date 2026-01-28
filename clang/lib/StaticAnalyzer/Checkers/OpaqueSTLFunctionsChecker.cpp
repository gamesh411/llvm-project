//===--- OpaqueSTLFunctionsChecker.cpp ------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Forces conservative evaluation for STL internal functions known to cause
// false positives. This prevents inlining and avoids wasting analysis time.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class OpaqueSTLFunctionsChecker : public Checker<eval::Call> {
public:
  bool evalCall(const CallEvent &Call, CheckerContext &C) const;

private:
  bool shouldForceConservativeEval(const CallEvent &Call) const;
};
} // anonymous namespace

bool OpaqueSTLFunctionsChecker::evalCall(const CallEvent &Call,
                                         CheckerContext &C) const {
  if (!shouldForceConservativeEval(Call))
    return false;

  // Force conservative evaluation by invalidating regions
  ProgramStateRef State = C.getState();
  State = Call.invalidateRegions(C.blockCount(), State);
  C.addTransition(State);
  return true;
}

bool OpaqueSTLFunctionsChecker::shouldForceConservativeEval(
    const CallEvent &Call) const {
  const Decl *D = Call.getDecl();
  if (!D || !AnalysisDeclContext::isInStdNamespace(D))
    return false;

  // Match methods by class name
  if (const auto *MD = dyn_cast<CXXMethodDecl>(D)) {
    const CXXRecordDecl *CD = MD->getParent();
    StringRef ClassName = CD->getName();
    
    // std::list - all methods
    if (ClassName == "list")
      return true;
    
    // std::basic_string - all methods
    if (ClassName == "basic_string")
      return true;
    
    // std::shared_ptr - all methods
    if (ClassName == "shared_ptr")
      return true;
    
    // Sort internal functions
    StringRef FuncName = MD->getName();
    if (FuncName == "__partition_with_equals_on_right" ||
        FuncName == "__introsort" ||
        FuncName == "__insertion_sort_incomplete")
      return true;
  }

  // Match constructors by class name
  if (const auto *CD = dyn_cast<CXXConstructorDecl>(D)) {
    const CXXRecordDecl *RD = CD->getParent();
    StringRef ClassName = RD->getName();
    
    if (ClassName == "__independent_bits_engine")
      return true;
  }

  // Match specific functions
  if (const auto *FD = dyn_cast<FunctionDecl>(D)) {
    StringRef FuncName = FD->getName();
    
    // __uninitialized_construct_buf_dispatch::__ucr
    if (FuncName == "__ucr") {
      if (const auto *MD = dyn_cast<CXXMethodDecl>(FD)) {
        const CXXRecordDecl *CD = MD->getParent();
        if (CD->getName() == "__uninitialized_construct_buf_dispatch")
          return true;
      }
    }
  }

  return false;
}

void ento::registerOpaqueSTLFunctionsChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<OpaqueSTLFunctionsChecker>();
}

bool ento::shouldRegisterOpaqueSTLFunctionsChecker(const CheckerManager &Mgr) {
  return true;
}
