//===-- MutexModeling.h ---------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines common data structures and modeling infrastructure for
// mutex-related checkers in the Clang Static Analyzer.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_STATICANALYZER_CHECKERS_MUTEXMODELING_H
#define LLVM_CLANG_STATICANALYZER_CHECKERS_MUTEXMODELING_H

#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerHelpers.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState_Fwd.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"

#include <iterator>
#include <utility>
#include <variant>

namespace clang {
namespace ento {

struct CritSectionMarker {
  const Expr *LockExpr{};
  const MemRegion *LockReg{};

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.Add(LockExpr);
    ID.Add(LockReg);
  }

  [[nodiscard]] constexpr bool
  operator==(const CritSectionMarker &Other) const noexcept {
    return LockExpr == Other.LockExpr && LockReg == Other.LockReg;
  }
  [[nodiscard]] constexpr bool
  operator!=(const CritSectionMarker &Other) const noexcept {
    return !(*this == Other);
  }
};

class CallDescriptionBasedMatcher {
  CallDescription LockFn;
  CallDescription UnlockFn;

public:
  CallDescriptionBasedMatcher(CallDescription &&LockFn,
                              CallDescription &&UnlockFn)
      : LockFn(std::move(LockFn)), UnlockFn(std::move(UnlockFn)) {}
  [[nodiscard]] bool matches(const CallEvent &Call, bool IsLock) const {
    if (IsLock) {
      return LockFn.matches(Call);
    }
    return UnlockFn.matches(Call);
  }
};

class FirstArgMutexDescriptor : public CallDescriptionBasedMatcher {
public:
  FirstArgMutexDescriptor(CallDescription &&LockFn, CallDescription &&UnlockFn)
      : CallDescriptionBasedMatcher(std::move(LockFn), std::move(UnlockFn)) {}

  [[nodiscard]] const MemRegion *getRegion(const CallEvent &Call, bool) const {
    return Call.getArgSVal(0).getAsRegion();
  }
};

class MemberMutexDescriptor : public CallDescriptionBasedMatcher {
public:
  MemberMutexDescriptor(CallDescription &&LockFn, CallDescription &&UnlockFn)
      : CallDescriptionBasedMatcher(std::move(LockFn), std::move(UnlockFn)) {}

  [[nodiscard]] const MemRegion *getRegion(const CallEvent &Call, bool) const {
    return cast<CXXMemberCall>(Call).getCXXThisVal().getAsRegion();
  }
};

class RAIIMutexDescriptor {
  mutable const IdentifierInfo *Guard{};
  mutable bool IdentifierInfoInitialized{};
  mutable llvm::SmallString<32> GuardName{};

  void initIdentifierInfo(const CallEvent &Call) const {
    if (!IdentifierInfoInitialized) {
      // In case of checking C code, or when the corresponding headers are not
      // included, we might end up query the identifier table every time when
      // this function is called instead of early returning it. To avoid this, a
      // bool variable (IdentifierInfoInitialized) is used and the function will
      // be run only once.
      const auto &ASTCtx = Call.getState()->getStateManager().getContext();
      Guard = &ASTCtx.Idents.get(GuardName);
    }
  }

  template <typename T> bool matchesImpl(const CallEvent &Call) const {
    const T *C = dyn_cast<T>(&Call);
    if (!C)
      return false;
    const IdentifierInfo *II =
        cast<CXXRecordDecl>(C->getDecl()->getParent())->getIdentifier();
    return II == Guard;
  }

public:
  RAIIMutexDescriptor(StringRef GuardName) : GuardName(GuardName) {}
  [[nodiscard]] bool matches(const CallEvent &Call, bool IsLock) const {
    initIdentifierInfo(Call);
    if (IsLock) {
      return matchesImpl<CXXConstructorCall>(Call);
    }
    return matchesImpl<CXXDestructorCall>(Call);
  }
  [[nodiscard]] const MemRegion *getRegion(const CallEvent &Call,
                                           bool IsLock) const {
    const MemRegion *LockRegion = nullptr;
    if (IsLock) {
      if (std::optional<SVal> Object = Call.getReturnValueUnderConstruction()) {
        LockRegion = Object->getAsRegion();
      }
    } else {
      LockRegion = cast<CXXDestructorCall>(Call).getCXXThisVal().getAsRegion();
    }
    return LockRegion;
  }
};

using MutexDescriptor =
    std::variant<FirstArgMutexDescriptor, MemberMutexDescriptor,
                 RAIIMutexDescriptor>;

} // namespace ento
} // namespace clang

// Iterator traits for ImmutableList data structure
// that enable the use of STL algorithms.
// TODO: Move these to llvm::ImmutableList when overhauling immutable data
// structures for proper iterator concept support.
template <>
struct std::iterator_traits<
    typename llvm::ImmutableList<clang::ento::CritSectionMarker>::iterator> {
  using iterator_category = std::forward_iterator_tag;
  using value_type = clang::ento::CritSectionMarker;
  using difference_type = std::ptrdiff_t;
  using reference = clang::ento::CritSectionMarker &;
  using pointer = clang::ento::CritSectionMarker *;
};

#endif // LLVM_CLANG_STATICANALYZER_CHECKERS_MUTEXMODELING_H
