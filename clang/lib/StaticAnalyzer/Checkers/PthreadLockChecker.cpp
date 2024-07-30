//===--- PthreadLockChecker.cpp - Check for locking problems ---*- C++ -*--===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines:
//  * PthreadLockChecker, a simple lock -> unlock checker.
//    Which also checks for XNU locks, which behave similarly enough to share
//    code.
//  * FuchsiaLocksChecker, which is also rather similar.
//  * C11LockChecker which also closely follows Pthread semantics.
//
//  TODO: Path notes.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#include "MutexModeling/MutexModelingAPI.h"

using namespace clang;
using namespace ento;
using namespace mutex_modeling;

namespace {

class PthreadLockChecker : public Checker<check::PostCall> {

public:
  enum CheckerKind {
    CK_PthreadLockChecker,
    CK_FuchsiaLockChecker,
    CK_C11LockChecker,
    CK_NumCheckKinds
  };

  bool ChecksEnabled[CK_NumCheckKinds] = {false};
  CheckerNameRef CheckNames[CK_NumCheckKinds];

  PthreadLockChecker() { RegisterEvents(); }

private:
  std::vector<EventDescriptor> EventsToModel{};
  void RegisterEvents() const {
    for (auto &&Event : EventsToModel) {
      RegisterEvent(Event);
    }
  }
  void reportBug(CheckerContext &C, std::unique_ptr<BugType> BT[],
                 const Expr *MtxExpr, CheckerKind CheckKind,
                 StringRef Desc) const;

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  // void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const;
  // ProgramStateRef
  // checkRegionChanges(ProgramStateRef State, const InvalidatedSymbols
  // *Symbols,
  //                    ArrayRef<const MemRegion *> ExplicitRegions,
  //                    ArrayRef<const MemRegion *> Regions,
  //                    const LocationContext *LCtx, const CallEvent *Call)
  //                    const;
  void printState(raw_ostream &Out, ProgramStateRef State, const char *NL,
                  const char *Sep) const override;

private:
  mutable std::unique_ptr<BugType> BT_doublelock[CK_NumCheckKinds];
  mutable std::unique_ptr<BugType> BT_doubleunlock[CK_NumCheckKinds];
  mutable std::unique_ptr<BugType> BT_destroylock[CK_NumCheckKinds];
  mutable std::unique_ptr<BugType> BT_initlock[CK_NumCheckKinds];
  mutable std::unique_ptr<BugType> BT_initlockPthread;
  mutable std::unique_ptr<BugType> BT_lor[CK_NumCheckKinds];

  void initBugType(CheckerKind CheckKind) const {
    if (BT_doublelock[CheckKind])
      return;
    BT_doublelock[CheckKind].reset(
        new BugType{CheckNames[CheckKind], "Double locking", "Lock checker"});
    BT_doubleunlock[CheckKind].reset(
        new BugType{CheckNames[CheckKind], "Double unlocking", "Lock checker"});
    BT_destroylock[CheckKind].reset(new BugType{
        CheckNames[CheckKind], "Use destroyed lock", "Lock checker"});
    BT_initlock[CheckKind].reset(new BugType{
        CheckNames[CheckKind], "Init invalid lock", "Lock checker"});
    BT_lor[CheckKind].reset(new BugType{CheckNames[CheckKind],
                                        "Lock order reversal", "Lock checker"});
  }

  [[nodiscard]] constexpr PthreadLockChecker::CheckerKind
  detectCheckerKind(mutex_modeling::EventMarker EV) const noexcept {
    switch (EV.Library) {
    case mutex_modeling::LibraryKind::Pthread:
      return PthreadLockChecker::CK_PthreadLockChecker;
    case mutex_modeling::LibraryKind::Fuchsia:
      return PthreadLockChecker::CK_FuchsiaLockChecker;
    case mutex_modeling::LibraryKind::C11:
      return PthreadLockChecker::CK_C11LockChecker;
    default:
      llvm_unreachable("Unknown locking library");
    }
  }

  void checkInitEvent(const EventMarker &LastEvent, CheckerContext &C) const;
  void checkAcquireEvent(const EventMarker &LastEvent, CheckerContext &C) const;
  void checkReleaseEvent(const EventMarker &LastEvent, CheckerContext &C) const;
  void checkDestroyEvent(const EventMarker &LastEvent, CheckerContext &C) const;
};
} // end anonymous namespace

void PthreadLockChecker::checkInitEvent(const EventMarker &LastEvent,
                                        CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const LockStateKind *const LockState =
      State->get<LockStates>(LastEvent.MutexRegion);

  if (!LockState) {
    return;
  }

  if (*LockState == LockStateKind::Error_DoubleInit) {
    reportBug(C, BT_initlock, LastEvent.EventExpr, detectCheckerKind(LastEvent),
              "This lock has already been initialized");
  } else if (*LockState == LockStateKind::Error_DoubleInitWhileLocked) {
    reportBug(C, BT_initlock, LastEvent.EventExpr, detectCheckerKind(LastEvent),
              "This lock is still being held");
  }
}

void PthreadLockChecker::checkAcquireEvent(const EventMarker &LastEvent,
                                           CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const LockStateKind *const LockState =
      State->get<LockStates>(LastEvent.MutexRegion);

  if (!LockState) {
    return;
  }

  if (*LockState == LockStateKind::Error_DoubleLock) {
    reportBug(C, BT_doublelock, LastEvent.EventExpr,
              detectCheckerKind(LastEvent),
              "This lock has already been acquired");
  } else if (*LockState == LockStateKind::Error_LockDestroyed) {
    reportBug(C, BT_destroylock, LastEvent.EventExpr,
              detectCheckerKind(LastEvent),
              "This lock has already been destroyed");
  }
}

void PthreadLockChecker::checkReleaseEvent(const EventMarker &LastEvent,
                                           CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const LockStateKind *const LockState =
      State->get<LockStates>(LastEvent.MutexRegion);

  if (!LockState) {
    return;
  }

  if (*LockState == LockStateKind::Error_DoubleUnlock) {
    reportBug(C, BT_doubleunlock, LastEvent.EventExpr,
              detectCheckerKind(LastEvent),
              "This lock has already been unlocked");
  } else if (*LockState == LockStateKind::Error_UnlockDestroyed) {
    reportBug(C, BT_destroylock, LastEvent.EventExpr,
              detectCheckerKind(LastEvent),
              "This lock has already been destroyed");
  } else if (*LockState == LockStateKind::Error_LockReversal) {
    reportBug(C, BT_lor, LastEvent.EventExpr, detectCheckerKind(LastEvent),
              "This was not the most recently acquired lock");
  }
}

void PthreadLockChecker::checkDestroyEvent(const EventMarker &LastEvent,
                                           CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const LockStateKind *const LockState =
      State->get<LockStates>(LastEvent.MutexRegion);

  if (!LockState || *LockState == LockStateKind::Destroyed) {
    return;
  }

  if (*LockState == LockStateKind::Error_DestroyLocked) {
    reportBug(C, BT_destroylock, LastEvent.EventExpr,
              detectCheckerKind(LastEvent), "This lock is still locked");
  } else if (*LockState == LockStateKind::Error_DoubleDestroy)
    reportBug(C, BT_destroylock, LastEvent.EventExpr,
              detectCheckerKind(LastEvent),
              "This lock has already been destroyed");
}

void PthreadLockChecker::checkPostCall(const CallEvent &Call,
                                       CheckerContext &C) const {

  ProgramStateRef State = C.getState();

  const auto &MTXEvents = State->get<MutexEvents>();

  if (MTXEvents.isEmpty()) {
    return;
  }

  const auto &LastEvent = MTXEvents.getHead();

  if (!ChecksEnabled[detectCheckerKind(LastEvent)])
    return;

  switch (LastEvent.Kind) {
  case EventKind::Init:
    checkInitEvent(LastEvent, C);
    break;
  case EventKind::Acquire:
  case EventKind::TryAcquire:
    checkAcquireEvent(LastEvent, C);
    break;
  case EventKind::Release:
    checkReleaseEvent(LastEvent, C);
    break;
  case EventKind::Destroy:
    checkDestroyEvent(LastEvent, C);
    break;
  default:
    llvm_unreachable("Unknown event kind");
  }
}

void PthreadLockChecker::reportBug(CheckerContext &C,
                                   std::unique_ptr<BugType> BT[],
                                   const Expr *MtxExpr, CheckerKind CheckKind,
                                   StringRef Desc) const {
  ExplodedNode *N = C.generateErrorNode();
  if (!N)
    return;
  initBugType(CheckKind);
  auto Report =
      std::make_unique<PathSensitiveBugReport>(*BT[CheckKind], Desc, N);
  Report->addRange(MtxExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

void PthreadLockChecker::printState(raw_ostream &Out, ProgramStateRef State,
                                    const char *NL, const char *Sep) const {
  mutex_modeling::printState(Out, State, NL, Sep);
}

void ento::registerPthreadLockBase(CheckerManager &mgr) {
  mgr.registerChecker<PthreadLockChecker>();
}

bool ento::shouldRegisterPthreadLockBase(const CheckerManager &mgr) {
  return true;
}

void ento::registerPthreadLockChecker(CheckerManager &CM) {
  PthreadLockChecker *ImplChecker = CM.getChecker<PthreadLockChecker>();
  ImplChecker->ChecksEnabled[PthreadLockChecker::CK_PthreadLockChecker] = true;
  ImplChecker->CheckNames[PthreadLockChecker::CK_PthreadLockChecker] =
      CM.getCurrentCheckerName();

  RegisterEvent(
      EventDescriptor{MakeFirstArgExtractor({"pthread_mutex_init"}, 2),
                      EventKind::Init, LibraryKind::Pthread});
  RegisterEvent(
      EventDescriptor{MakeFirstArgExtractor({"pthread_mutex_init"}, 2),
                      EventKind::Init, LibraryKind::Pthread});
  RegisterEvent(EventDescriptor{MakeFirstArgExtractor({"pthread_mutex_lock"}),
                                EventKind::Acquire, LibraryKind::Pthread,
                                SemanticsKind::PthreadSemantics});
  RegisterEvent(EventDescriptor{
      MakeFirstArgExtractor({"pthread_mutex_trylock"}), EventKind::TryAcquire,
      LibraryKind::Pthread, SemanticsKind::PthreadSemantics});
  RegisterEvent(EventDescriptor{MakeFirstArgExtractor({"pthread_mutex_unlock"}),
                                EventKind::Release, LibraryKind::Pthread});
  RegisterEvent(EventDescriptor{MakeFirstArgExtractor({"pthread_mutex_destroy"}),
                                EventKind::Destroy, LibraryKind::Pthread});
}

bool ento::shouldRegisterPthreadLockChecker(const CheckerManager &CM) {
  return true;
}

void ento::registerFuchsiaLockChecker(CheckerManager &CM) {
  PthreadLockChecker *ImplChecker = CM.getChecker<PthreadLockChecker>();
  ImplChecker->ChecksEnabled[PthreadLockChecker::CK_FuchsiaLockChecker] = true;
  ImplChecker->CheckNames[PthreadLockChecker::CK_FuchsiaLockChecker] =
      CM.getCurrentCheckerName();
}

bool ento::shouldRegisterFuchsiaLockChecker(const CheckerManager &CM) {
  return true;
}

void ento::registerC11LockChecker(CheckerManager &CM) {
  PthreadLockChecker *ImplChecker = CM.getChecker<PthreadLockChecker>();
  ImplChecker->ChecksEnabled[PthreadLockChecker::CK_C11LockChecker] = true;
  ImplChecker->CheckNames[PthreadLockChecker::CK_C11LockChecker] =
      CM.getCurrentCheckerName();

  RegisterEvent(EventDescriptor{MakeFirstArgExtractor({"lck_mtx_lock"}),
                                EventKind::Acquire, LibraryKind::C11,
                                SemanticsKind::XNUSemantics});
  RegisterEvent(EventDescriptor{MakeFirstArgExtractor({"lck_mtx_try_lock"}),
                                EventKind::TryAcquire, LibraryKind::C11,
                                SemanticsKind::XNUSemantics});
  RegisterEvent(EventDescriptor{MakeFirstArgExtractor({"lck_mtx_unlock"}),
                                EventKind::Release, LibraryKind::C11,
                                SemanticsKind::XNUSemantics});
}

bool ento::shouldRegisterC11LockChecker(const CheckerManager &CM) {
  return true;
}
