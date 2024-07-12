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

#include "MutexRegionExtractor.h"
#include "clang/Basic/IdentifierTable.h"

namespace clang {

class Expr;

namespace ento {

class MemRegion;

namespace mutex_modeling {

enum class EventKind { Init, Acquire, TryAcquire, Release, Destroy };

enum class SyntaxKind { FirstArg, Member, RAII };

enum class SemanticsKind { NotApplicable = 0, PthreadSemantics, XNUSemantics };

enum class LockStateKind {
  Unlocked,
  Locked,
  Destroyed,
  UntouchedAndPossiblyDestroyed,
  UnlockedAndPossiblyDestroyed,
  Error_DoubleInit,
  Error_DoubleInitWhileLocked,
};

struct EventDescriptor {
  MutexRegionExtractor Trigger;
  EventKind Kind{};
  SemanticsKind Semantics{};

  // TODO: Modernize to spaceship when C++20 is available.
  [[nodiscard]] constexpr bool
  operator!=(const EventDescriptor &Other) const noexcept {
    return !(Trigger == Other.Trigger) || Kind != Other.Kind ||
           Semantics != Other.Semantics;
  }
  [[nodiscard]] constexpr bool
  operator==(const EventDescriptor &Other) const noexcept {
    return !(*this != Other);
  }
};

struct EventMarker {
  EventKind Kind{};
  SemanticsKind Semantics{};
  const IdentifierInfo *Event;
  const clang::Expr *EventExpr{};
  const clang::ento::MemRegion *MutexRegion{};

  // TODO: Modernize to spaceship when C++20 is available.
  [[nodiscard]] constexpr bool
  operator!=(const EventMarker &Other) const noexcept {
    return Event != Other.Event || Kind != Other.Kind ||
           Semantics != Other.Semantics || LockState != Other.LockState ||
           EventExpr != Other.EventExpr || MutexRegion != Other.MutexRegion;
  }
  [[nodiscard]] constexpr bool
  operator==(const EventMarker &Other) const noexcept {
    return !(*this != Other);
  }
};

struct CritSectionMarker {
  const clang::Expr *BeginExpr;
  const clang::ento::MemRegion *MutexRegion;

  explicit CritSectionMarker(const clang::Expr *BeginExpr,
                             const clang::ento::MemRegion *MutexRegion)
      : BeginExpr(BeginExpr), MutexRegion(MutexRegion) {}

  // TODO: Modernize to spaceship when C++20 is available.
  [[nodiscard]] constexpr bool
  operator!=(const CritSectionMarker &Other) const noexcept {
    return BeginExpr != Other.BeginExpr || MutexRegion != Other.MutexRegion;
  }
  [[nodiscard]] constexpr bool
  operator==(const CritSectionMarker &Other) const noexcept {
    return !(*this != Other);
  }
};

} // namespace mutex_modeling
} // namespace ento
} // namespace clang

#endif
