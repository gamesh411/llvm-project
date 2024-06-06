//===--- MutexModeling.h - Modeling of mutexes ----------------------------===//
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

#ifndef LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_MUTEXMODELING_H
#define LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_MUTEXMODELING_H

#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/StringExtras.h"

#include "MutexModelingGDM.h"

namespace clang {
namespace ento {
namespace mutex_modeling {
inline const NoteTag *createCritSectionNote(CritSectionMarker M,
                                            CheckerContext &C) {
  return C.getNoteTag([M](const PathSensitiveBugReport &BR,
                          llvm::raw_ostream &OS) {
    const auto CritSectionBegins =
        BR.getErrorNode()->getState()->get<ActiveCritSections>();
    llvm::SmallVector<CritSectionMarker, 4> LocksForMutex;
    llvm::copy_if(
        CritSectionBegins, std::back_inserter(LocksForMutex),
        [M](const auto &Marker) { return Marker.LockReg == M.LockReg; });
    if (LocksForMutex.empty())
      return;

    // As the ImmutableList builds the locks by prepending them, we
    // reverse the list to get the correct order.
    std::reverse(LocksForMutex.begin(), LocksForMutex.end());

    // Find the index of the lock expression in the list of all locks for a
    // given mutex (in acquisition order).
    const CritSectionMarker *const Position =
        llvm::find_if(std::as_const(LocksForMutex), [M](const auto &Marker) {
          return Marker.LockExpr == M.LockExpr;
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
