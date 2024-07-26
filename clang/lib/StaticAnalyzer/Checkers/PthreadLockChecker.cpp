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

class PthreadLockChecker : public Checker<check::PostCall> {
  // , check::DeadSymbols,
  //                                          check::RegionChanges> {

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
  std::vector<EventDescriptor> EventsToModel{
      EventDescriptor{MakeFirstArgExtractor({"pthread_mutex_init"}, 2),
                      EventKind::Init, LibraryKind::Pthread}};
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
  void checkTryAcquireEvent(const EventMarker &LastEvent,
                            CheckerContext &C) const;
  void checkReleaseEvent(const EventMarker &LastEvent, CheckerContext &C) const;
  void checkDestroyEvent(const EventMarker &LastEvent, CheckerContext &C) const;
};
} // end anonymous namespace

void PthreadLockChecker::checkInitEvent(const EventMarker &LastEvent,
                                        CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const LockStateKind *const LockState =
      State->get<LockStates>(LastEvent.MutexRegion);

  if (!LockState || *LockState == LockStateKind::Destroyed) {
    return;
  }

  bool IsError = false;
  StringRef Message;
  switch (*LockState) {
  case LockStateKind::Error_DoubleInit: {
    IsError = true;
    Message = "This lock has already been initialized";
    break;
  }
  case LockStateKind::Error_DoubleInitWhileLocked: {
    IsError = true;
    Message = "This lock is still being held";
    break;
  }
  default: {
  }
  }

  if (!IsError) {
    return;
  }

  reportBug(C, BT_initlock, LastEvent.EventExpr, detectCheckerKind(LastEvent),
            Message);
}

void PthreadLockChecker::checkAcquireEvent(const EventMarker &LastEvent,
                                           CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const LockStateKind *const LockState =
      State->get<LockStates>(LastEvent.MutexRegion);
}

void PthreadLockChecker::checkPostCall(const CallEvent &Call,
                                       CheckerContext &C) const {

  ProgramStateRef State = C.getState();

  const auto &MTXEvents = State->get<MutexEvents>();

  if (MTXEvents.isEmpty()) {
    return;
  }

  const auto &LastEvent = MTXEvents.getHead();

  switch (LastEvent.Kind) {
  case EventKind::Init:
    checkInitEvent(LastEvent, C);
    break;
  case EventKind::Acquire:
    checkAcquireEvent(LastEvent, C);
    break;
  case EventKind::TryAcquire:
    checkTryAcquireEvent(LastEvent, C);
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

#if 0
void PthreadLockChecker::AcquirePthreadLock(const CallEvent &Call,
                                            CheckerContext &C,
                                            CheckerKind CheckKind) const {
  AcquireLockAux(Call, C, Call.getArgExpr(0), Call.getArgSVal(0), false,
                 PthreadSemantics, CheckKind);
}

void PthreadLockChecker::AcquireXNULock(const CallEvent &Call,
                                        CheckerContext &C,
                                        CheckerKind CheckKind) const {
  AcquireLockAux(Call, C, Call.getArgExpr(0), Call.getArgSVal(0), false,
                 XNUSemantics, CheckKind);
}

void PthreadLockChecker::TryPthreadLock(const CallEvent &Call,
                                        CheckerContext &C,
                                        CheckerKind CheckKind) const {
  AcquireLockAux(Call, C, Call.getArgExpr(0), Call.getArgSVal(0), true,
                 PthreadSemantics, CheckKind);
}

void PthreadLockChecker::TryXNULock(const CallEvent &Call, CheckerContext &C,
                                    CheckerKind CheckKind) const {
  AcquireLockAux(Call, C, Call.getArgExpr(0), Call.getArgSVal(0), true,
                 PthreadSemantics, CheckKind);
}

void PthreadLockChecker::TryFuchsiaLock(const CallEvent &Call,
                                        CheckerContext &C,
                                        CheckerKind CheckKind) const {
  AcquireLockAux(Call, C, Call.getArgExpr(0), Call.getArgSVal(0), true,
                 PthreadSemantics, CheckKind);
}

void PthreadLockChecker::TryC11Lock(const CallEvent &Call, CheckerContext &C,
                                    CheckerKind CheckKind) const {
  AcquireLockAux(Call, C, Call.getArgExpr(0), Call.getArgSVal(0), true,
                 PthreadSemantics, CheckKind);
}

void PthreadLockChecker::AcquireLockAux(const CallEvent &Call,
                                        CheckerContext &C, const Expr *MtxExpr,
                                        SVal MtxVal, bool IsTryLock,
                                        enum LockingSemantics Semantics,
                                        CheckerKind CheckKind) const {
  if (!ChecksEnabled[CheckKind])
    return;

  const MemRegion *lockR = MtxVal.getAsRegion();
  if (!lockR)
    return;

  ProgramStateRef state = C.getState();
  const SymbolRef *sym = state->get<DestroyRetVal>(lockR);
  if (sym)
    state = resolvePossiblyDestroyedMutex(state, lockR, sym);

  if (const LockState *LState = state->get<LockMap>(lockR)) {
    if (LState->isLocked()) {
      reportBug(C, BT_doublelock, MtxExpr, CheckKind,
                "This lock has already been acquired");
      return;
    } else if (LState->isDestroyed()) {
      reportBug(C, BT_destroylock, MtxExpr, CheckKind,
                "This lock has already been destroyed");
      return;
    }
  }

  ProgramStateRef lockSucc = state;
  if (IsTryLock) {
    // Bifurcate the state, and allow a mode where the lock acquisition fails.
    SVal RetVal = Call.getReturnValue();
    if (auto DefinedRetVal = RetVal.getAs<DefinedSVal>()) {
      ProgramStateRef lockFail;
      switch (Semantics) {
      case PthreadSemantics:
        std::tie(lockFail, lockSucc) = state->assume(*DefinedRetVal);
        break;
      case XNUSemantics:
        std::tie(lockSucc, lockFail) = state->assume(*DefinedRetVal);
        break;
      default:
        llvm_unreachable("Unknown tryLock locking semantics");
      }
      assert(lockFail && lockSucc);
      C.addTransition(lockFail);
    }
    // We might want to handle the case when the mutex lock function was inlined
    // and returned an Unknown or Undefined value.
  } else if (Semantics == PthreadSemantics) {
    // Assume that the return value was 0.
    SVal RetVal = Call.getReturnValue();
    if (auto DefinedRetVal = RetVal.getAs<DefinedSVal>()) {
      // FIXME: If the lock function was inlined and returned true,
      // we need to behave sanely - at least generate sink.
      lockSucc = state->assume(*DefinedRetVal, false);
      assert(lockSucc);
    }
    // We might want to handle the case when the mutex lock function was inlined
    // and returned an Unknown or Undefined value.
  } else {
    // XNU locking semantics return void on non-try locks
    assert((Semantics == XNUSemantics) && "Unknown locking semantics");
    lockSucc = state;
  }

  // Record that the lock was acquired.
  lockSucc = lockSucc->add<LockSet>(lockR);
  lockSucc = lockSucc->set<LockMap>(lockR, LockState::getLocked());
  C.addTransition(lockSucc);
}

void PthreadLockChecker::ReleaseAnyLock(const CallEvent &Call,
                                        CheckerContext &C,
                                        CheckerKind CheckKind) const {
  ReleaseLockAux(Call, C, Call.getArgExpr(0), Call.getArgSVal(0), CheckKind);
}

void PthreadLockChecker::ReleaseLockAux(const CallEvent &Call,
                                        CheckerContext &C, const Expr *MtxExpr,
                                        SVal MtxVal,
                                        CheckerKind CheckKind) const {
  if (!ChecksEnabled[CheckKind])
    return;

  const MemRegion *lockR = MtxVal.getAsRegion();
  if (!lockR)
    return;

  ProgramStateRef state = C.getState();
  const SymbolRef *sym = state->get<DestroyRetVal>(lockR);
  if (sym)
    state = resolvePossiblyDestroyedMutex(state, lockR, sym);

  if (const LockState *LState = state->get<LockMap>(lockR)) {
    if (LState->isUnlocked()) {
      reportBug(C, BT_doubleunlock, MtxExpr, CheckKind,
                "This lock has already been unlocked");
      return;
    } else if (LState->isDestroyed()) {
      reportBug(C, BT_destroylock, MtxExpr, CheckKind,
                "This lock has already been destroyed");
      return;
    }
  }

  LockSetTy LS = state->get<LockSet>();

  if (!LS.isEmpty()) {
    const MemRegion *firstLockR = LS.getHead();
    if (firstLockR != lockR) {
      reportBug(C, BT_lor, MtxExpr, CheckKind,
                "This was not the most recently acquired lock. Possible lock "
                "order reversal");
      return;
    }
    // Record that the lock was released.
    state = state->set<LockSet>(LS.getTail());
  }

  state = state->set<LockMap>(lockR, LockState::getUnlocked());
  C.addTransition(state);
}

void PthreadLockChecker::DestroyPthreadLock(const CallEvent &Call,
                                            CheckerContext &C,
                                            CheckerKind CheckKind) const {
  DestroyLockAux(Call, C, Call.getArgExpr(0), Call.getArgSVal(0),
                 PthreadSemantics, CheckKind);
}

void PthreadLockChecker::DestroyXNULock(const CallEvent &Call,
                                        CheckerContext &C,
                                        CheckerKind CheckKind) const {
  DestroyLockAux(Call, C, Call.getArgExpr(0), Call.getArgSVal(0), XNUSemantics,
                 CheckKind);
}

void PthreadLockChecker::DestroyLockAux(const CallEvent &Call,
                                        CheckerContext &C, const Expr *MtxExpr,
                                        SVal MtxVal,
                                        enum LockingSemantics Semantics,
                                        CheckerKind CheckKind) const {
  if (!ChecksEnabled[CheckKind])
    return;

  const MemRegion *LockR = MtxVal.getAsRegion();
  if (!LockR)
    return;

  ProgramStateRef State = C.getState();

  const SymbolRef *sym = State->get<DestroyRetVal>(LockR);
  if (sym)
    State = resolvePossiblyDestroyedMutex(State, LockR, sym);

  const LockState *LState = State->get<LockMap>(LockR);
  // Checking the return value of the destroy method only in the case of
  // PthreadSemantics
  if (Semantics == PthreadSemantics) {
    if (!LState || LState->isUnlocked()) {
      SymbolRef sym = Call.getReturnValue().getAsSymbol();
      if (!sym) {
        State = State->remove<LockMap>(LockR);
        C.addTransition(State);
        return;
      }
      State = State->set<DestroyRetVal>(LockR, sym);
      if (LState && LState->isUnlocked())
        State = State->set<LockMap>(
            LockR, LockState::getUnlockedAndPossiblyDestroyed());
      else
        State = State->set<LockMap>(
            LockR, LockState::getUntouchedAndPossiblyDestroyed());
      C.addTransition(State);
      return;
    }
  } else {
    if (!LState || LState->isUnlocked()) {
      State = State->set<LockMap>(LockR, LockState::getDestroyed());
      C.addTransition(State);
      return;
    }
  }

  StringRef Message = LState->isLocked()
                          ? "This lock is still locked"
                          : "This lock has already been destroyed";

  reportBug(C, BT_destroylock, MtxExpr, CheckKind, Message);
}

void PthreadLockChecker::InitAnyLock(const CallEvent &Call, CheckerContext &C,
                                     CheckerKind CheckKind) const {
  InitLockAux(Call, C, Call.getArgExpr(0), Call.getArgSVal(0), CheckKind);
}

void PthreadLockChecker::InitLockAux(const CallEvent &Call, CheckerContext &C,
                                     const Expr *MtxExpr, SVal MtxVal,
                                     CheckerKind CheckKind) const {
  if (!ChecksEnabled[CheckKind])
    return;

  const MemRegion *LockR = MtxVal.getAsRegion();
  if (!LockR)
    return;

  ProgramStateRef State = C.getState();

  const SymbolRef *sym = State->get<DestroyRetVal>(LockR);
  if (sym)
    State = resolvePossiblyDestroyedMutex(State, LockR, sym);

  const struct LockState *LState = State->get<LockMap>(LockR);
  if (!LState || LState->isDestroyed()) {
    State = State->set<LockMap>(LockR, LockState::getUnlocked());
    C.addTransition(State);
    return;
  }

  StringRef Message = LState->isLocked()
                          ? "This lock is still being held"
                          : "This lock has already been initialized";

  reportBug(C, BT_initlock, MtxExpr, CheckKind, Message);
}

void PthreadLockChecker::checkDeadSymbols(SymbolReaper &SymReaper,
                                          CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  for (auto I : State->get<DestroyRetVal>()) {
    // Once the return value symbol dies, no more checks can be performed
    // against it. See if the return value was checked before this point.
    // This would remove the symbol from the map as well.
    if (SymReaper.isDead(I.second))
      State = resolvePossiblyDestroyedMutex(State, I.first, &I.second);
  }

  for (auto I : State->get<LockMap>()) {
    // Stop tracking dead mutex regions as well.
    if (!SymReaper.isLiveRegion(I.first)) {
      State = State->remove<LockMap>(I.first);
      State = State->remove<DestroyRetVal>(I.first);
    }
  }

  // TODO: We probably need to clean up the lock stack as well.
  // It is tricky though: even if the mutex cannot be unlocked anymore,
  // it can still participate in lock order reversal resolution.

  C.addTransition(State);
}

ProgramStateRef PthreadLockChecker::checkRegionChanges(
    ProgramStateRef State, const InvalidatedSymbols *Symbols,
    ArrayRef<const MemRegion *> ExplicitRegions,
    ArrayRef<const MemRegion *> Regions, const LocationContext *LCtx,
    const CallEvent *Call) const {

  bool IsLibraryFunction = false;
  if (Call && Call->isGlobalCFunction()) {
    // Avoid invalidating mutex state when a known supported function is called.
    if (PThreadCallbacks.lookup(*Call) || FuchsiaCallbacks.lookup(*Call) ||
        C11Callbacks.lookup(*Call))
      return State;

    if (Call->isInSystemHeader())
      IsLibraryFunction = true;
  }

  for (auto R : Regions) {
    // We assume that system library function wouldn't touch the mutex unless
    // it takes the mutex explicitly as an argument.
    // FIXME: This is a bit quadratic.
    if (IsLibraryFunction && !llvm::is_contained(ExplicitRegions, R))
      continue;

    State = State->remove<LockMap>(R);
    State = State->remove<DestroyRetVal>(R);

    // TODO: We need to invalidate the lock stack as well. This is tricky
    // to implement correctly and efficiently though, because the effects
    // of mutex escapes on lock order may be fairly varied.
  }

  return State;
}
#endif

void ento::registerPthreadLockBase(CheckerManager &mgr) {
  mgr.registerChecker<PthreadLockChecker>();
}

bool ento::shouldRegisterPthreadLockBase(const CheckerManager &mgr) {
  return true;
}

#define REGISTER_CHECKER(name, library)                                        \
  void ento::register##name(CheckerManager &mgr) {                             \
    PthreadLockChecker *checker = mgr.getChecker<PthreadLockChecker>();        \
    checker->ChecksEnabled[PthreadLockChecker::CK_##name] = true;              \
    checker->CheckNames[PthreadLockChecker::CK_##name] =                       \
        mgr.getCurrentCheckerName();                                           \
  }                                                                            \
  bool ento::shouldRegister##name(const CheckerManager &mgr) { return true; }

REGISTER_CHECKER(PthreadLockChecker, LibraryKind::Pthread)
REGISTER_CHECKER(FuchsiaLockChecker, LibraryKind::Fuchsia)
REGISTER_CHECKER(C11LockChecker, LibraryKind::C11)
