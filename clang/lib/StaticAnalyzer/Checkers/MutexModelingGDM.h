//===--- MutexModelingGDM.h - Modeling of mutexes -------------------------===//
//----------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Defines the GDM definitions for tracking mutex states.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_MUTEXMODELINGGDM_H
#define LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_MUTEXMODELINGGDM_H

#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"

namespace clang {

class Expr;

namespace ento {

class MemRegion;

namespace mutex_modeling {

/// Control dependecy factors

enum LockingSemantics { NotApplicable = 0, PthreadSemantics, XNUSemantics };

enum CheckerKind {
  CK_BlockInCriticalSectionChecker,
  CK_PthreadLockChecker,
  CK_FuchsiaLockChecker,
  CK_C11LockChecker,
  CK_NumCheckKinds
};

struct LockState {
  enum Kind {
    Destroyed,
    Locked,
    Unlocked,
    UntouchedAndPossiblyDestroyed,
    UnlockedAndPossiblyDestroyed
  } K;

private:
  LockState(Kind K) : K(K) {}

public:
  static LockState getLocked() { return LockState(Locked); }
  static LockState getUnlocked() { return LockState(Unlocked); }
  static LockState getDestroyed() { return LockState(Destroyed); }
  static LockState getUntouchedAndPossiblyDestroyed() {
    return LockState(UntouchedAndPossiblyDestroyed);
  }
  static LockState getUnlockedAndPossiblyDestroyed() {
    return LockState(UnlockedAndPossiblyDestroyed);
  }

  bool operator==(const LockState &X) const { return K == X.K; }

  bool isLocked() const { return K == Locked; }
  bool isUnlocked() const { return K == Unlocked; }
  bool isDestroyed() const { return K == Destroyed; }
  bool isUntouchedAndPossiblyDestroyed() const {
    return K == UntouchedAndPossiblyDestroyed;
  }
  bool isUnlockedAndPossiblyDestroyed() const {
    return K == UnlockedAndPossiblyDestroyed;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const { ID.AddInteger(K); }
};

struct CritSectionMarker {
  const clang::Expr *LockExpr{};
  const clang::ento::MemRegion *LockReg{};

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

// GDM-related handle-types for tracking mutex states.
class ActiveCritSections {};
using ActiveCritSectionsTy = llvm ::ImmutableList<CritSectionMarker>;

} // namespace mutex_modeling
} // namespace ento
} // namespace clang

// shorthand for the type of the GDM handle.
namespace {
using MutexModelingCritSectionMarker =
    clang::ento::mutex_modeling::CritSectionMarker;
} // namespace

// Iterator traits for ImmutableList data structure
// that enable the use of STL algorithms.
namespace std {
// TODO: Move these to llvm::ImmutableList when overhauling immutable data
// structures for proper iterator concept support.

template <>
struct iterator_traits<
    typename llvm::ImmutableList<MutexModelingCritSectionMarker>::iterator> {
  using iterator_category = std::forward_iterator_tag;
  using value_type = MutexModelingCritSectionMarker;
  using difference_type = std::ptrdiff_t;
  using reference = MutexModelingCritSectionMarker &;
  using pointer = MutexModelingCritSectionMarker *;
};
} // namespace std

// FIXME: ProgramState macros are not used here, because the visibility of these
// GDM entries must span multiple translation units (multiple checkers).
namespace clang {
namespace ento {
template <>
struct ProgramStateTrait<clang::ento::mutex_modeling::ActiveCritSections>
    : public ProgramStatePartialTrait<
          clang::ento::mutex_modeling::ActiveCritSectionsTy> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};
} // namespace ento
} // namespace clang

#endif
