//===--- MutexModelingAPI.h - API for modeling mutexes --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Defines inter-checker API for tracking and manipulating the
// modeled state of locked mutexes in the GDM.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_MUTEXMODELINGAPI_H
#define LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_MUTEXMODELINGAPI_H

#include "MutexModelingDomain.h"
#include "MutexModelingGDM.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/StringExtras.h"

namespace clang {

namespace ento {
class BugType;
namespace mutex_modeling {

inline llvm::SmallSet<const BugType *, 8> RegisteredCheckers{};

inline void RegisterCheckerForMutexModeling(const BugType *BT) {
  RegisteredCheckers.insert(BT);
}

inline bool IsCheckerRegisteredForMutexModeling(const BugType *BT) {
  return RegisteredCheckers.contains(BT);
}

inline bool AreAnyCritsectionsActive(CheckerContext &C) {
  return !C.getState()->get<CritSections>().isEmpty();
}

inline const NoteTag *CreateMutexCritSectionNote(CritSectionMarker M,
                                                 CheckerContext &C) {
  return C.getNoteTag([M](const PathSensitiveBugReport &BR,
                          llvm::raw_ostream &OS) {
    if (!IsCheckerRegisteredForMutexModeling(&BR.getBugType()))
      return;
    const auto CritSectionBegins =
        BR.getErrorNode()->getState()->get<CritSections>();
    llvm::SmallVector<CritSectionMarker, 4> LocksForMutex;
    llvm::copy_if(CritSectionBegins, std::back_inserter(LocksForMutex),
                  [M](const auto &Marker) {
                    return Marker.MutexRegion == M.MutexRegion;
                  });
    if (LocksForMutex.empty())
      return;

    // As the ImmutableList builds the locks by prepending them, we
    // reverse the list to get the correct order.
    std::reverse(LocksForMutex.begin(), LocksForMutex.end());

    // Find the index of the lock expression in the list of all locks for a
    // given mutex (in acquisition order).
    const CritSectionMarker *const Position =
        llvm::find_if(std::as_const(LocksForMutex), [M](const auto &Marker) {
          return Marker.BeginExpr == M.BeginExpr;
        });
    if (Position == LocksForMutex.end())
      return;

    // If there is only one lock event, we don't need to specify how many times
    // the critical section was entered.
    if (LocksForMutex.size() == 1) {
      OS << "Entering critical section here";
      return;
    }

    const auto IndexOfLock =
        std::distance(std::as_const(LocksForMutex).begin(), Position);

    const auto OrdinalOfLock = IndexOfLock + 1;
    OS << "Entering critical section for the " << OrdinalOfLock
       << llvm::getOrdinalSuffix(OrdinalOfLock) << " time here";
  });
}

} // namespace mutex_modeling
} // namespace ento
} // namespace clang

#endif
