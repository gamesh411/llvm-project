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

#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"

namespace clang {

class Expr;

namespace ento {

class MemRegion;

namespace mutex_modeling {

enum class Event { Init, Acquire, TryAcquire, Release, Destroy };

enum class Syntax { FirstArg, Member, RAII };

enum class LockingSemantics {
  NotApplicable = 0,
  PthreadSemantics,
  XNUSemantics
};

enum class LockState {
  Unlocked,
  Locked,
  Destroyed,
  UntouchedAndPossiblyDestroyed,
  UnlockedAndPossiblyDestroyed
};

struct EventDescriptor {
  CallDescription Trigger;
  Event Kind{};
  Syntax Syntax{};
  LockingSemantics Semantics{};

  [[nodiscard]] constexpr bool
  operator!=(const EventDescriptor &Other) const noexcept {
    return Trigger != Other.Trigger || Kind != Other.Kind ||
           Syntax != Other.Syntax || Semantics != Other.Semantics;
  }
  [[nodiscard]] constexpr bool
  operator==(const EventDescriptor &Other) const noexcept {
    return !(*this != Other);
  }
};

struct EventMarker {
  EventDescriptor Event{};
  LockState LockState{};
  const clang::Expr *EventExpr{};
  const clang::ento::MemRegion *MutexRegion{};

  [[nodiscard]] constexpr bool
  operator!=(const EventMarker &Other) const noexcept {
    return Event != Other.Event || LockState != Other.LockState ||
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
