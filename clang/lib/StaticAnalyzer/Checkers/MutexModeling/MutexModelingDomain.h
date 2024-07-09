//===--- MutexModelingDomain.h - Common vocabulary for modeling mutexes ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Defines common types and related functions used in the mutex modeling domain.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_MUTEXMODELINGDOMAIN_H
#define LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_MUTEXMODELINGDOMAIN_H

namespace clang {

class Expr;

namespace ento {

class MemRegion;

namespace mutex_modeling {

enum class EventKind { Init, Acquire, TryAcquire, Release, Destroy };

enum class SyntaxKind { FirstArg, Member, RAII };

enum class LockingSemanticsKind { PthreadSemantics, XNUSemantics };

enum class LockStateKind {
  Unlocked,
  Locked,
  Destroyed,
  UntouchedAndPossiblyDestroyed,
  UnlockedAndPossiblyDestroyed
};

struct EventDescriptor {
  EventKind Kind{};
  SyntaxKind Syntax{};
  LockingSemanticsKind Semantics{};

  [[nodiscard]] constexpr bool
  operator==(const EventDescriptor &Other) const noexcept {
    return Kind == Other.Kind && Syntax == Other.Syntax &&
           Semantics == Other.Semantics;
  }
  [[nodiscard]] constexpr bool
  operator!=(const EventDescriptor &Other) const noexcept {
    return !(*this == Other);
  }
};

struct EventMarker {
  EventDescriptor Event{};
  LockStateKind LockState{};
  const clang::Expr *EventExpr{};
  const clang::ento::MemRegion *MutexRegion{};

  [[nodiscard]] constexpr bool
  operator==(const EventMarker &Other) const noexcept {
    return Event == Other.Event && LockState == Other.LockState &&
           EventExpr == Other.EventExpr && MutexRegion == Other.MutexRegion;
  }
  [[nodiscard]] constexpr bool
  operator!=(const EventMarker &Other) const noexcept {
    return !(*this == Other);
  }
};

struct CritSectionMarker {
  const clang::Expr *BeginExpr;
  const clang::ento::MemRegion *MutexRegion;

  [[nodiscard]] constexpr bool
  operator==(const CritSectionMarker &Other) const noexcept {
    return BeginExpr == Other.BeginExpr && MutexRegion == Other.MutexRegion;
  }
  [[nodiscard]] constexpr bool
  operator!=(const CritSectionMarker &Other) const noexcept {
    return !(*this == Other);
  }
};

} // namespace mutex_modeling
} // namespace ento
} // namespace clang

#endif
