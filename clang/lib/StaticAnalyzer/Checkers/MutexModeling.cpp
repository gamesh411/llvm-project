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
  std::vector<EventDescriptor> handledEvents = getHandledEvents();

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  std::unique_ptr<BugType> BT_initlock = std::make_unique<BugType>(
      this->getCheckerName(), "Init invalid lock", "Lock checker");
  ProgramStateRef handleInit(const EventDescriptor &Event, const MemRegion *MTX,
                             const Expr *MTXExpr, const CallEvent &Call,
                             ProgramStateRef State, CheckerContext &C) const;
  ProgramStateRef handleEvent(const EventDescriptor &Event,
                              const MemRegion *MTX, const Expr *MTXExpr,
                              const CallEvent &Call, ProgramStateRef State,
                              CheckerContext &C) const;
};

} // namespace

ProgramStateRef
MutexModeling::handleInit(const EventDescriptor &Event, const MemRegion *MTX,
                          const Expr *MTXExpr, const CallEvent &Call,
                          ProgramStateRef State, CheckerContext &C) const {
  assert(MTX && "should only be called with a mutex region");
  assert(MTXExpr && "should only be called with a valid mutex expression");

  State = State->add<MutexEvents>(EventMarker{
      Event.Kind, Event.Semantics, Call.getCalleeIdentifier(), MTXExpr, MTX});

  const LockStateKind *LState = State->get<LockStates>(MTX);
  if (!LState || *LState == LockStateKind::Destroyed) {
    return State->set<LockStates>(MTX, LockStateKind::Unlocked);
  }

  // We are here if three is an init event on a lock that is modelled, and it
  // is not in destroyed state. The bugreporting should be done in the
  // reporting checker and not it the modeling, but we still want to be
  // efficient.
  StringRef Message;
  if (*LState == LockStateKind::Locked) {
    Message = "This lock is still being held";
    State =
        State->set<LockStates>(MTX, LockStateKind::Error_DoubleInitWhileLocked);
  } else {
    Message = "This lock has already been initialized";
    State = State->set<LockStates>(MTX, LockStateKind::Error_DoubleInit);
  }

  // TODO: put this part in the reporting checker

  ExplodedNode *N = C.generateErrorNode();
  if (!N)
    return State;
  auto Report =
      std::make_unique<PathSensitiveBugReport>(BT_initlock.get(), Message, N);
  Report->addRange(MTXExpr->getSourceRange());
  C.emitReport(std::move(Report));

  return State;
}

ProgramStateRef
MutexModeling::handleEvent(const EventDescriptor &Event, const MemRegion *MTX,
                           const Expr *MTXExpr, const CallEvent &Call,
                           ProgramStateRef State, CheckerContext &C) const {
  assert(MTX && "should only be called with a mutex region");
  assert(MTXExpr && "should only be called with a valid mutex expression");

  switch (Event.Kind) {
  case EventKind::Init:
    return handleInit(Event, MTX, MTXExpr, Call, State, C);
    break;
  default:
    llvm_unreachable("Unhandled event kind!");
#if 0
  case EventKind::Acquire:
    handleAcquire(Event, Call, C);
    break;
  case EventKind::TryAcquire:
    handleTryAcquire(Event, Call, C);
    break;
  case EventKind::Release:
    handleRelease(Event, Call, C);
    break;
  case EventKind::Destroy:
    handleDestroy(Event, Call, C);
    break;
#endif
  }
}

void MutexModeling::checkPostCall(const CallEvent &Call,
                                  CheckerContext &C) const {
  // FIXME: Try to handle cases when the implementation was inlined rather than
  // just giving up.
  if (C.wasInlined)
    return;

  ProgramStateRef State = C.getState();
  for (auto &&Event : handledEvents) {
    if (matches(Event.Trigger, Call)) {
      const MemRegion *MTX = getRegion(Event.Trigger, Call);
      if (!MTX)
        continue;
      const Expr *MTXExpr = Call.getOriginExpr();
      if (!MTXExpr)
        continue;
      State = doResolvePossiblyDestroyedMutex(State, MTX);
      State = handleEvent(Event, MTX, MTXExpr, Call, State, C);
      C.addTransition(State);
    }
  }

} // namespace

namespace clang {
namespace ento {
// Checker registration
void registerMutexModeling(CheckerManager &mgr) {
  mgr.registerChecker<MutexModeling>();
}
bool shouldRegisterMutexModeling(const CheckerManager &) { return true; }
} // namespace ento
} // namespace clang
