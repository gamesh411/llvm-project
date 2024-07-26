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
#include "MutexModeling/MutexModelingDefs.h"
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
                                              const SymbolRef *Sym) {
  const LockStateKind *LState = State->get<LockStates>(LockReg);
  // Existence in DestroyRetVal ensures existence in LockMap.
  // Existence in Destroyed also ensures that the lock state for lockR is either
  // UntouchedAndPossiblyDestroyed or UnlockedAndPossiblyDestroyed.
  assert(LState);
  assert(*LState == LockStateKind::UntouchedAndPossiblyDestroyed ||
         *LState == LockStateKind::UnlockedAndPossiblyDestroyed);

  ConstraintManager &CMgr = State->getConstraintManager();
  ConditionTruthVal RetZero = CMgr.isNull(State, *Sym);
  if (RetZero.isConstrainedFalse()) {
    switch (*LState) {
    case LockStateKind::UntouchedAndPossiblyDestroyed: {
      State = State->remove<LockStates>(LockReg);
      break;
    }
    case LockStateKind::UnlockedAndPossiblyDestroyed: {
      State = State->set<LockStates>(LockReg, LockStateKind::Unlocked);
      break;
    }
    default: {
      State = State->set<LockStates>(LockReg, LockStateKind::Destroyed);
    }
    }
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

void updateCritSectionOnLock(const MutexRegionExtractor &LockDescriptor,
                             const CallEvent &Call, CheckerContext &C) {
  const MemRegion *MutexRegion = getRegion(LockDescriptor, Call);
  if (!MutexRegion)
    return;

  const CritSectionMarker MarkToAdd{Call.getOriginExpr(), MutexRegion};
  ProgramStateRef StateWithLockEvent =
      C.getState()->add<CritSections>(MarkToAdd);
  C.addTransition(StateWithLockEvent, CreateMutexCritSectionNote(MarkToAdd, C));
}

void updateCriticalSectionOnUnlock(const EventDescriptor &UnlockDescriptor,
                                   const CallEvent &Call, CheckerContext &C) {
  const MemRegion *MutexRegion = getRegion(UnlockDescriptor.Trigger, Call);
  if (!MutexRegion)
    return;

  ProgramStateRef State = C.getState();
  const auto ActiveSections = State->get<CritSections>();
  const auto MostRecentLock =
      llvm::find_if(ActiveSections, [MutexRegion](auto &&Marker) {
        return Marker.MutexRegion == MutexRegion;
      });
  if (MostRecentLock == ActiveSections.end())
    return;

  // Build a new ImmutableList without this element.
  auto &Factory = State->get_context<CritSections>();
  llvm::ImmutableList<CritSectionMarker> NewList = Factory.getEmptyList();
  for (auto It = ActiveSections.begin(), End = ActiveSections.end(); It != End;
       ++It) {
    if (It != MostRecentLock)
      NewList = Factory.add(*It, NewList);
  }

  C.addTransition(State->set<CritSections>(NewList));
}

class MutexModeling : public Checker<check::PostCall> {
public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  mutable std::unique_ptr<BugType> BT_initlock;
  ProgramStateRef handleInit(const EventDescriptor &Event, const MemRegion *MTX,
                             const CallEvent &Call, ProgramStateRef State,
                             CheckerContext &C) const;
  ProgramStateRef handleAcquire(const EventDescriptor &Event,
                                const MemRegion *MTX, const CallEvent &Call,
                                ProgramStateRef State, CheckerContext &C) const;
  ProgramStateRef handleTryAcquire(const EventDescriptor &Event,
                                   const MemRegion *MTX, const CallEvent &Call,
                                   ProgramStateRef State,
                                   CheckerContext &C) const;
  ProgramStateRef handleRelease(const EventDescriptor &Event,
                                const MemRegion *MTX, const CallEvent &Call,
                                ProgramStateRef State, CheckerContext &C) const;
  ProgramStateRef handleDestroy(const EventDescriptor &Event,
                                const MemRegion *MTX, const CallEvent &Call,
                                ProgramStateRef State, CheckerContext &C) const;
  ProgramStateRef handleEvent(const EventDescriptor &Event,
                              const MemRegion *MTX, const CallEvent &Call,
                              ProgramStateRef State, CheckerContext &C) const;
};

} // namespace

ProgramStateRef MutexModeling::handleInit(const EventDescriptor &Event,
                                          const MemRegion *MTX,
                                          const CallEvent &Call,
                                          ProgramStateRef State,
                                          CheckerContext &C) const {
  assert(MTX && "should only be called with a mutex region");

  const LockStateKind *LState = State->get<LockStates>(MTX);

  if (!LState)
    return State->set<LockStates>(MTX, LockStateKind::Unlocked);

  switch (*LState) {
  case (LockStateKind::Destroyed): {
    return State->set<LockStates>(MTX, LockStateKind::Unlocked);
  }
  case (LockStateKind::Locked): {
    return State->set<LockStates>(MTX,
                                  LockStateKind::Error_DoubleInitWhileLocked);
  }
  default: {
    return State->set<LockStates>(MTX, LockStateKind::Error_DoubleInit);
  }
  }
}

static ProgramStateRef doAcquireCommonLogic(ProgramStateRef State,
                                            const MemRegion *MTX) {
  const LockStateKind *LState = State->get<LockStates>(MTX);

  if (!LState)
    State = State->set<LockStates>(MTX, LockStateKind::Locked);
  else if (*LState == LockStateKind::Locked)
    State = State->set<LockStates>(MTX, LockStateKind::Error_DoubleLock);
  if (*LState == LockStateKind::Destroyed)
    State = State->set<LockStates>(MTX, LockStateKind::Error_LockDestroyed);

  return State;
}

ProgramStateRef MutexModeling::handleAcquire(const EventDescriptor &Event,
                                             const MemRegion *MTX,
                                             const CallEvent &Call,
                                             ProgramStateRef State,
                                             CheckerContext &C) const {

  State = doAcquireCommonLogic(State, MTX);

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
    break;
  }
  case SemanticsKind::XNUSemantics:
    // XNU semantics return void on non-try locks.
    break;
  default:
    llvm_unreachable(
        "Acquire events should have either Pthread or XNU semantics");
  }

  return State;
}

ProgramStateRef MutexModeling::handleTryAcquire(const EventDescriptor &Event,
                                                const MemRegion *MTX,
                                                const CallEvent &Call,
                                                ProgramStateRef State,
                                                CheckerContext &C) const {

  State = doAcquireCommonLogic(State, MTX);

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
      llvm_unreachable("Unknown tryLock locking semantics");
    }

    // This is the bifurcation point in the ExplodedGraph, we do not need to
    // pass the new ExplodedGraph node because we do not plan on building this
    // failed case part forward in this checker.
    C.addTransition(LockFail);

    // Pass the state where the locking succeeded onwards.
    State = LockSucc;
    // We might want to handle the case when the mutex lock function was inlined
    // and returned an Unknown or Undefined value.
  }
  return State;
}

ProgramStateRef MutexModeling::handleRelease(const EventDescriptor &Event,
                                             const MemRegion *MTX,
                                             const CallEvent &Call,
                                             ProgramStateRef State,
                                             CheckerContext &C) const {

  const LockStateKind *LState = State->get<LockStates>(MTX);

  if (!LState)
    return State->set<LockStates>(MTX, LockStateKind::Unlocked);

  if (*LState == LockStateKind::Unlocked)
    return State->set<LockStates>(MTX, LockStateKind::Error_DoubleUnlock);

  if (*LState == LockStateKind::Destroyed)
    return State->set<LockStates>(MTX, LockStateKind::Error_UnlockDestroyed);

  // Check if the currently released mutex is also the most recently locked one.
  // If not, report a lock reversal bug.
  // NOTE: MutexEvents stores events in reverse order as the ImmutableList data
  // structure grows towards its Head element.
  const auto &Events = State->get<MutexEvents>();
  bool IsLockReversal = false;
  for (const auto &Event : Events) {
    if (Event.Kind == EventKind::Acquire) {
      IsLockReversal = Event.MutexRegion != MTX;
      break;
    }
  }

  if (IsLockReversal) {
    return State->set<LockStates>(MTX, LockStateKind::Error_LockReversal);
  }

  return State->set<LockStates>(MTX, LockStateKind::Unlocked);
}

ProgramStateRef MutexModeling::handleEvent(const EventDescriptor &Event,
                                           const MemRegion *MTX,
                                           const CallEvent &Call,
                                           ProgramStateRef State,
                                           CheckerContext &C) const {
  assert(MTX && "should only be called with a mutex region");

  State = State->add<MutexEvents>(
      EventMarker{Event.Kind, Event.Semantics, Event.Library,
                  Call.getCalleeIdentifier(), Call.getOriginExpr(), MTX});

  switch (Event.Kind) {
  case EventKind::Init:
    return handleInit(Event, MTX, Call, State, C);
    break;
  case EventKind::Acquire:
    handleAcquire(Event, MTX, Call, State, C);
    break;
  case EventKind::TryAcquire:
    handleTryAcquire(Event, MTX, Call, State, C);
    break;
  case EventKind::Release:
    handleRelease(Event, MTX, Call, State, C);
    break;
  case EventKind::Destroy:
    handleDestroy(Event, MTX, Call, State, C);
    break;
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
      State = handleEvent(Event, MTX, Call, State, C);
      C.addTransition(State);
    }
  }
}

namespace clang {
namespace ento {
// Checker registration
void registerMutexModeling(CheckerManager &mgr) {
  mgr.registerChecker<MutexModeling>();
  RegisterEvent(
      EventDescriptor{MakeFirstArgExtractor({"pthread_mutex_init"}, 2),
                      EventKind::Init, LibraryKind::Pthread});
}
bool shouldRegisterMutexModeling(const CheckerManager &) { return true; }
} // namespace ento
} // namespace clang
