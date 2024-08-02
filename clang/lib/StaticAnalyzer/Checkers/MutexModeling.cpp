//===--- MutexModeling.cpp - Modeling of mutexes --------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Defines modeling checker for tracking mutex states.
//
//===----------------------------------------------------------------------===//

#include "MutexModeling/MutexModelingAPI.h"
#include "MutexModeling/MutexModelingDomain.h"
#include "MutexModeling/MutexRegionExtractor.h"

#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include <memory>

using namespace clang;
using namespace ento;
using namespace mutex_modeling;

namespace {

// When a lock is destroyed, in some semantics(like PthreadSemantics) we are not
// sure if the destroy call has succeeded or failed, and the lock enters one of
// the 'possibly destroyed' state. There is a short time frame for the
// programmer to check the return value to see if the lock was successfully
// destroyed. Before we model the next operation over that lock, we call this
// function to see if the return value was checked by now and set the lock state
// - either to destroyed state or back to its previous state.

// In PthreadSemantics, pthread_mutex_destroy() returns zero if the lock is
// successfully destroyed and it returns a non-zero value otherwise.
ProgramStateRef resolvePossiblyDestroyedMutex(ProgramStateRef State,
                                              const MemRegion *LockReg,
                                              const SymbolRef *LockReturnSym) {
  const LockStateKind *LockState = State->get<LockStates>(LockReg);
  // Existence in DestroyRetVal ensures existence in LockMap.
  // Existence in Destroyed also ensures that the lock state for lockR is either
  // UntouchedAndPossiblyDestroyed or UnlockedAndPossiblyDestroyed.
  assert(LockState);
  assert(*LockState == LockStateKind::UntouchedAndPossiblyDestroyed ||
         *LockState == LockStateKind::UnlockedAndPossiblyDestroyed);

  ConstraintManager &CMgr = State->getConstraintManager();
  ConditionTruthVal RetZero = CMgr.isNull(State, *LockReturnSym);
  if (RetZero.isConstrainedFalse()) {
    switch (*LockState) {
    case LockStateKind::UntouchedAndPossiblyDestroyed: {
      State = State->remove<LockStates>(LockReg);
      break;
    }
    case LockStateKind::UnlockedAndPossiblyDestroyed: {
      State = State->set<LockStates>(LockReg, LockStateKind::Unlocked);
      break;
    }
    default:
      llvm_unreachable("Unknown lock state for a lock inside DestroyRetVal");
    }
  } else {
    State = State->set<LockStates>(LockReg, LockStateKind::Destroyed);
  }

  // Removing the map entry (LockReg, sym) from DestroyRetVal as the lock
  // state is now resolved.
  return State->remove<DestroyedRetVals>(LockReg);
}

ProgramStateRef doResolvePossiblyDestroyedMutex(ProgramStateRef State,
                                                const MemRegion *MTX) {
  assert(MTX && "should only be called with a mutex region");

  if (const SymbolRef *Sym = State->get<DestroyedRetVals>(MTX))
    return resolvePossiblyDestroyedMutex(State, MTX, Sym);
  return State;
}

class MutexModeling : public Checker<check::PostCall, check::DeadSymbols,
                                     check::RegionChanges> {
public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const;

  ProgramStateRef
  checkRegionChanges(ProgramStateRef State, const InvalidatedSymbols *Symbols,
                     ArrayRef<const MemRegion *> ExplicitRegions,
                     ArrayRef<const MemRegion *> Regions,
                     const LocationContext *LCtx, const CallEvent *Call) const;

private:
  mutable std::unique_ptr<BugType> BT_initlock;

  // When handling events, NoteTags can be placed on ProgramPoints. This struct
  // supports returning both the resulting ProgramState and a NoteTag.
  struct ModelingResult {
    ProgramStateRef State;
    const NoteTag *Note = nullptr;
  };

  ModelingResult handleInit(const EventDescriptor &Event, const MemRegion *MTX,
                            const CallEvent &Call, ProgramStateRef State,
                            CheckerContext &C) const;
  ModelingResult onSuccessfullAcquire(const MemRegion *MTX,
                                      const CallEvent &Call,
                                      ProgramStateRef State,
                                      CheckerContext &C) const;
  ModelingResult markCritSection(ModelingResult InputState,
                                 const MemRegion *MTX, const CallEvent &Call,
                                 CheckerContext &C) const;
  ModelingResult handleAcquire(const EventDescriptor &Event,
                               const MemRegion *MTX, const CallEvent &Call,
                               ProgramStateRef State, CheckerContext &C) const;
  ModelingResult handleTryAcquire(const EventDescriptor &Event,
                                  const MemRegion *MTX, const CallEvent &Call,
                                  ProgramStateRef State,
                                  CheckerContext &C) const;
  ModelingResult handleRelease(const EventDescriptor &Event,
                               const MemRegion *MTX, const CallEvent &Call,
                               ProgramStateRef State, CheckerContext &C) const;
  ModelingResult handleDestroy(const EventDescriptor &Event,
                               const MemRegion *MTX, const CallEvent &Call,
                               ProgramStateRef State, CheckerContext &C) const;
  ModelingResult handleEvent(const EventDescriptor &Event, const MemRegion *MTX,
                             const CallEvent &Call, ProgramStateRef State,
                             CheckerContext &C) const;
};

} // namespace

MutexModeling::ModelingResult
MutexModeling::handleInit(const EventDescriptor &Event, const MemRegion *MTX,
                          const CallEvent &Call, ProgramStateRef State,
                          CheckerContext &C) const {
  ModelingResult Result{State->set<LockStates>(MTX, LockStateKind::Unlocked)};

  const LockStateKind *LockState = State->get<LockStates>(MTX);

  if (!LockState)
    return Result;

  switch (*LockState) {
  case (LockStateKind::Destroyed): {
    Result.State = State->set<LockStates>(MTX, LockStateKind::Unlocked);
    break;
  }
  case (LockStateKind::Locked): {
    Result.State =
        State->set<LockStates>(MTX, LockStateKind::Error_DoubleInitWhileLocked);
    break;
  }
  default: {
    Result.State = State->set<LockStates>(MTX, LockStateKind::Error_DoubleInit);
    break;
  }
  }

  return Result;
}

MutexModeling::ModelingResult
MutexModeling::markCritSection(MutexModeling::ModelingResult InputState,
                               const MemRegion *MTX, const CallEvent &Call,
                               CheckerContext &C) const {
  const CritSectionMarker MarkToAdd{Call.getOriginExpr(), MTX};
  return {InputState.State->add<CritSections>(MarkToAdd),
          CreateMutexCritSectionNote(MarkToAdd, C)};
}

MutexModeling::ModelingResult
MutexModeling::onSuccessfullAcquire(const MemRegion *MTX, const CallEvent &Call,
                                    ProgramStateRef State,
                                    CheckerContext &C) const {
  ModelingResult Result{State};

  const LockStateKind *LockState = State->get<LockStates>(MTX);

  if (!LockState) {
    Result.State = Result.State->set<LockStates>(MTX, LockStateKind::Locked);
    Result = markCritSection(Result, MTX, Call, C);
    return Result;
  }

  switch (*LockState) {
  case LockStateKind::Unlocked:
    Result.State = Result.State->set<LockStates>(MTX, LockStateKind::Locked);
    Result = markCritSection(Result, MTX, Call, C);
    break;
  case LockStateKind::Locked:
    Result.State =
        Result.State->set<LockStates>(MTX, LockStateKind::Error_DoubleLock);
    break;
  case LockStateKind::Destroyed:
    Result.State =
        Result.State->set<LockStates>(MTX, LockStateKind::Error_LockDestroyed);
    break;
  default:
    break;
  }

  return Result;
}

MutexModeling::ModelingResult
MutexModeling::handleAcquire(const EventDescriptor &Event, const MemRegion *MTX,
                             const CallEvent &Call, ProgramStateRef State,
                             CheckerContext &C) const {

  switch (Event.Semantics) {
  case SemanticsKind::PthreadSemantics: {
    // Assume that the return value was 0.
    SVal RetVal = Call.getReturnValue();
    if (auto DefinedRetVal = RetVal.getAs<DefinedSVal>()) {
      // FIXME: If the lock function was inlined and returned true,
      // we need to behave sanely - at least generate sink.
      State = State->assume(*DefinedRetVal, false);
      assert(State);
    }
    // We might want to handle the case when the mutex lock function was
    // inlined and returned an Unknown or Undefined value.
    break;
  }
  case SemanticsKind::XNUSemantics:
    // XNU semantics return void on non-try locks.
    break;
  default:
    llvm_unreachable(
        "Acquire events should have either Pthread or XNU semantics");
  }

  return onSuccessfullAcquire(MTX, Call, State, C);
}

MutexModeling::ModelingResult MutexModeling::handleTryAcquire(
    const EventDescriptor &Event, const MemRegion *MTX, const CallEvent &Call,
    ProgramStateRef State, CheckerContext &C) const {

  ModelingResult Result{State};
  // Bifurcate the state, and allow a mode where the lock acquisition fails.
  ProgramStateRef LockSucc;
  SVal RetVal = Call.getReturnValue();
  if (auto DefinedRetVal = RetVal.getAs<DefinedSVal>()) {
    ProgramStateRef LockFail;
    switch (Event.Semantics) {
    case SemanticsKind::PthreadSemantics:
      std::tie(LockFail, LockSucc) = State->assume(*DefinedRetVal);
      break;
    case SemanticsKind::XNUSemantics:
      std::tie(LockSucc, LockFail) = State->assume(*DefinedRetVal);
      break;
    default:
      llvm_unreachable("Unknown TryLock locking semantics");
    }
    assert(LockFail && LockSucc && "Bifurcation point in ExplodedGraph");

    // This is the bifurcation point in the ExplodedGraph, we do not need to
    // return the new ExplodedGraph node because we do not plan on building this
    // lock-failed case path in this checker.
    C.addTransition(LockFail);
  }

  // Pass the state where the locking succeeded onwards.
  Result = onSuccessfullAcquire(MTX, Call, LockSucc, C);
  return Result;
}

MutexModeling::ModelingResult
MutexModeling::handleRelease(const EventDescriptor &Event, const MemRegion *MTX,
                             const CallEvent &Call, ProgramStateRef State,
                             CheckerContext &C) const {

  ModelingResult Result{State};

  const LockStateKind *LockState = Result.State->get<LockStates>(MTX);

  if (!LockState) {
    Result.State = Result.State->set<LockStates>(MTX, LockStateKind::Unlocked);
    return Result;
  }

  if (*LockState == LockStateKind::Unlocked) {
    Result.State =
        State->set<LockStates>(MTX, LockStateKind::Error_DoubleUnlock);
    return Result;
  }

  if (*LockState == LockStateKind::Destroyed) {
    Result.State =
        State->set<LockStates>(MTX, LockStateKind::Error_UnlockDestroyed);
    return Result;
  }

  const auto ActiveSections = State->get<CritSections>();
  const auto MostRecentLockForMTX =
      llvm::find_if(ActiveSections,
                    [MTX](auto &&Marker) { return Marker.MutexRegion == MTX; });

  // In a non-empty critical section list, if the most recent lock is for
  // another mutex, then ther is a lock reversal.
  bool IsLockInversion = MostRecentLockForMTX != ActiveSections.begin();

  // NOTE: IsLockInversion -> !ActiveSections.isEmpty()
  assert((!IsLockInversion || !ActiveSections.isEmpty()) &&
         "The existance of an inversion implies that the list is not empty");

  if (IsLockInversion) {
    Result.State =
        State->set<LockStates>(MTX, LockStateKind::Error_LockReversal);
    // Build a new ImmutableList without this element.
    auto &Factory = Result.State->get_context<CritSections>();
    llvm::ImmutableList<CritSectionMarker> WithoutThisLock =
        Factory.getEmptyList();
    for (auto It = ActiveSections.begin(), End = ActiveSections.end();
         It != End; ++It) {
      if (It != MostRecentLockForMTX)
        WithoutThisLock = Factory.add(*It, WithoutThisLock);
    }
    Result.State = Result.State->set<CritSections>(WithoutThisLock);
    return Result;
  }

  Result.State = Result.State->set<LockStates>(MTX, LockStateKind::Unlocked);
  // If there is no lock inversion, we can just remove the last crit section.
  // NOTE: It should be safe to call getTail on an empty list
  Result.State = Result.State->set<CritSections>(ActiveSections.getTail());

  return Result;
}

MutexModeling::ModelingResult
MutexModeling::handleDestroy(const EventDescriptor &Event, const MemRegion *MTX,
                             const CallEvent &Call, ProgramStateRef State,
                             CheckerContext &C) const {

  // Original implementation:
  //
  // const LockState *LState = State->get<LockMap>(LockR);
  // // Checking the return value of the destroy method only in the case of
  // // PthreadSemantics
  // if (Semantics == PthreadSemantics) {
  //   if (!LState || LState->isUnlocked()) {
  //     SymbolRef sym = Call.getReturnValue().getAsSymbol();
  //     if (!sym) {
  //       State = State->remove<LockMap>(LockR);
  //       C.addTransition(State);
  //       return;
  //     }
  //     State = State->set<DestroyRetVal>(LockR, sym);
  //     if (LState && LState->isUnlocked())
  //       State = State->set<LockMap>(
  //           LockR, LockState::getUnlockedAndPossiblyDestroyed());
  //     else
  //       State = State->set<LockMap>(
  //           LockR, LockState::getUntouchedAndPossiblyDestroyed());
  //     C.addTransition(State);
  //     return;
  //   }
  // } else {
  //   if (!LState || LState->isUnlocked()) {
  //     State = State->set<LockMap>(LockR, LockState::getDestroyed());
  //     C.addTransition(State);
  //     return;
  //   }
  // }

  // StringRef Message = LState->isLocked()
  //                         ? "This lock is still locked"
  //                         : "This lock has already been destroyed";

  // reportBug(C, BT_destroylock, MtxExpr, CheckKind, Message);

  // New implementation:

  ModelingResult Result{State};

  const LockStateKind *LockState = Result.State->get<LockStates>(MTX);

  if (Event.Semantics == SemanticsKind::PthreadSemantics) {
    if (!LockState || *LockState == LockStateKind::Unlocked) {
      SymbolRef Sym = Call.getReturnValue().getAsSymbol();
      if (!Sym) {
        Result.State = Result.State->remove<LockStates>(MTX);
        return Result;
      }
      Result.State = Result.State->set<DestroyedRetVals>(MTX, Sym);
      Result.State = Result.State->set<LockStates>(
          MTX, LockState && *LockState == LockStateKind::Unlocked
                   ? LockStateKind::UnlockedAndPossiblyDestroyed
                   : LockStateKind::UntouchedAndPossiblyDestroyed);
      return Result;
    }
  } else {
    if (!LockState || *LockState == LockStateKind::Unlocked) {
      Result.State =
          Result.State->set<LockStates>(MTX, LockStateKind::Destroyed);
      return Result;
    }
  }

  if (*LockState == LockStateKind::Locked) {
    Result.State =
        Result.State->set<LockStates>(MTX, LockStateKind::Error_DestroyLocked);
    return Result;
  }

  if (*LockState == LockStateKind::Destroyed) {
    Result.State =
        Result.State->set<LockStates>(MTX, LockStateKind::Error_DoubleDestroy);
    return Result;
  }

  assert(LockState && *LockState != LockStateKind::Unlocked &&
         *LockState != LockStateKind::Locked &&
         *LockState != LockStateKind::Destroyed &&
         "We can only get here if we came from an error-state to begin with");

  return Result;
}

MutexModeling::ModelingResult
MutexModeling::handleEvent(const EventDescriptor &Event, const MemRegion *MTX,
                           const CallEvent &Call, ProgramStateRef State,
                           CheckerContext &C) const {
  assert(MTX && "should only be called with a mutex region");

  State = State->add<MutexEvents>(
      EventMarker{Event.Kind, Event.Semantics, Event.Library,
                  Call.getCalleeIdentifier(), Call.getOriginExpr(), MTX});

  switch (Event.Kind) {
  case EventKind::Init:
    return handleInit(Event, MTX, Call, State, C);
  case EventKind::Acquire:
    return handleAcquire(Event, MTX, Call, State, C);
  case EventKind::TryAcquire:
    return handleTryAcquire(Event, MTX, Call, State, C);
  case EventKind::Release:
    return handleRelease(Event, MTX, Call, State, C);
  case EventKind::Destroy:
    return handleDestroy(Event, MTX, Call, State, C);
  default:
    llvm_unreachable("Unhandled event kind!");
  }
}

void MutexModeling::checkPostCall(const CallEvent &Call,
                                  CheckerContext &C) const {
  // FIXME: Try to handle cases when the implementation was inlined rather
  // than just giving up.
  if (C.wasInlined)
    return;

  ProgramStateRef State = C.getState();
  for (auto &&Event : RegisteredEvents) {
    if (matches(Event.Trigger, Call)) {
      const MemRegion *MTX = getRegion(Event.Trigger, Call);
      if (!MTX)
        continue;
      State = doResolvePossiblyDestroyedMutex(State, MTX);
      ModelingResult Result = handleEvent(Event, MTX, Call, State, C);
      C.addTransition(Result.State, Result.Note);
    }
  }
}

void MutexModeling::checkDeadSymbols(SymbolReaper &SymReaper,
                                     CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  for (auto I : State->get<DestroyedRetVals>()) {
    // Once the return value symbol dies, no more checks can be performed
    // against it. See if the return value was checked before this point.
    // This would remove the symbol from the map as well.
    if (SymReaper.isDead(I.second))
      State = resolvePossiblyDestroyedMutex(State, I.first, &I.second);
  }

  for (auto I : State->get<LockStates>()) {
    // Stop tracking dead mutex regions as well.
    if (!SymReaper.isLiveRegion(I.first)) {
      State = State->remove<LockStates>(I.first);
      State = State->remove<DestroyedRetVals>(I.first);
    }
  }

  // TODO: We probably need to clean up the lock stack as well.
  // It is tricky though: even if the mutex cannot be unlocked anymore,
  // it can still participate in lock order reversal resolution.

  C.addTransition(State);
}

ProgramStateRef MutexModeling::checkRegionChanges(
    ProgramStateRef State, const InvalidatedSymbols *Symbols,
    ArrayRef<const MemRegion *> ExplicitRegions,
    ArrayRef<const MemRegion *> Regions, const LocationContext *LCtx,
    const CallEvent *Call) const {

  bool IsLibraryFunction = false;
  if (Call && Call->isGlobalCFunction()) {
    // Avoid invalidating mutex state when a known supported function is
    // called.
    for (auto &&Event : RegisteredEvents) {
      if (matches(Event.Trigger, *Call)) {
        return State;
      }
    }

    if (Call->isInSystemHeader())
      IsLibraryFunction = true;
  }

  for (auto R : Regions) {
    // We assume that system library function wouldn't touch the mutex unless
    // it takes the mutex explicitly as an argument.
    // FIXME: This is a bit quadratic.
    if (IsLibraryFunction && !llvm::is_contained(ExplicitRegions, R))
      continue;

    State = State->remove<LockStates>(R);
    State = State->remove<DestroyedRetVals>(R);

    // TODO: We need to invalidate the lock stack as well. This is tricky
    // to implement correctly and efficiently though, because the effects
    // of mutex escapes on lock order may be fairly varied.
  }

  return State;
}

namespace clang {
namespace ento {
// Checker registration
void registerMutexModeling(CheckerManager &CM) {
  CM.registerChecker<MutexModeling>();
}
bool shouldRegisterMutexModeling(const CheckerManager &) { return true; }
} // namespace ento
} // namespace clang
