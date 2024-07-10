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

#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/ADT/SmallVector.h"

using namespace clang;
using namespace ento;
using namespace mutex_modeling;

namespace {

class MutexModeling : public Checker<check::PostCall> {

  std::array<EventDescriptor, 64> HandledEvents{
      // Init kind
      // - Pthread
      EventDescriptor{CallDescription{CDM::CLibrary, {"pthread_mutex_init"}, 2},
                      EventKind::Init, SyntaxKind::FirstArg,
                      LockingSemanticsKind::NotApplicable},
      // TODO: pthread_rwlock_init(2 arguments).
      // TODO: lck_mtx_init(3 arguments).
      // TODO: lck_mtx_alloc_init(2 arguments) => returns the mutex.
      // TODO: lck_rw_init(3 arguments).
      // TODO: lck_rw_alloc_init(2 arguments) => returns the mutex.

      // - Fuchsia
      EventDescriptor{CallDescription{CDM::CLibrary, {"spin_lock_init"}, 1},
                      EventKind::Init, SyntaxKind::FirstArg,
                      LockingSemanticsKind::NotApplicable},

      // - C11
      EventDescriptor{CallDescription{CDM::CLibrary, {"mtx_init"}, 2},
                      EventKind::Init, SyntaxKind::FirstArg,
                      LockingSemanticsKind::NotApplicable},

      // Acquire kind
      // - Pthread
      //
      EventDescriptor{CallDescription{CDM::CLibrary, {"pthread_mutex_lock"}, 1},
                      EventKind::Acquire, SyntaxKind::FirstArg,
                      LockingSemanticsKind::PthreadSemantics},
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"pthread_rwlock_rdlock"}, 1},
          EventKind::Acquire, SyntaxKind::FirstArg,
          LockingSemanticsKind::PthreadSemantics},
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"pthread_rwlock_wrlock"}, 1},
          EventKind::Acquire, SyntaxKind::FirstArg,
          LockingSemanticsKind::PthreadSemantics},
      EventDescriptor{CallDescription{CDM::CLibrary, {"lck_mtx_lock"}, 1},
                      EventKind::Acquire, SyntaxKind::FirstArg,
                      LockingSemanticsKind::XNUSemantics},
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"lck_rw_lock_exclusive"}, 1},
          EventKind::Acquire, SyntaxKind::FirstArg,
          LockingSemanticsKind::XNUSemantics},
      EventDescriptor{CallDescription{CDM::CLibrary, {"lck_rw_lock_shared"}, 1},
                      EventKind::Acquire, SyntaxKind::FirstArg,
                      LockingSemanticsKind::XNUSemantics},

      // - Fuchsia
      EventDescriptor{CallDescription{CDM::CLibrary, {"spin_lock"}, 1},
                      EventKind::Acquire, SyntaxKind::FirstArg,
                      LockingSemanticsKind::PthreadSemantics},
      EventDescriptor{CallDescription{CDM::CLibrary, {"spin_lock_save"}, 3},
                      EventKind::Acquire, SyntaxKind::FirstArg,
                      LockingSemanticsKind::PthreadSemantics},
      EventDescriptor{CallDescription{CDM::CLibrary, {"sync_mutex_lock"}, 1},
                      EventKind::Acquire, SyntaxKind::FirstArg,
                      LockingSemanticsKind::PthreadSemantics},
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"sync_mutex_lock_with_waiter"}, 1},
          EventKind::Acquire, SyntaxKind::FirstArg,
          LockingSemanticsKind::PthreadSemantics},

      // - C11
      EventDescriptor{CallDescription{CDM::CLibrary, {"mtx_lock"}, 1},
                      EventKind::Acquire, SyntaxKind::FirstArg,
                      LockingSemanticsKind::PthreadSemantics},

      // - std
      EventDescriptor{
          CallDescription{CDM::CXXMethod, {"std", "mutex", "lock"}, 0},
          EventKind::Acquire, SyntaxKind::Member,
          LockingSemanticsKind::PthreadSemantics},
      EventDescriptor{CallDescription{CDM::CXXMethod, {"std", "lock_guard"}, 1},
                      EventKind::Acquire, SyntaxKind::RAII,
                      LockingSemanticsKind::PthreadSemantics},
      EventDescriptor{
          CallDescription{CDM::CXXMethod, {"std", "unique_lock"}, 1},
          EventKind::Acquire, SyntaxKind::RAII,
          LockingSemanticsKind::PthreadSemantics},

      // TryAcquire kind
      // - Pthread
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"pthread_mutex_trylock"}, 1},
          EventKind::TryAcquire, SyntaxKind::FirstArg,
          LockingSemanticsKind::PthreadSemantics},
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"pthread_rwlock_tryrdlock"}, 1},
          EventKind::TryAcquire, SyntaxKind::FirstArg,
          LockingSemanticsKind::PthreadSemantics},
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"pthread_rwlock_trywrlock"}, 1},
          EventKind::TryAcquire, SyntaxKind::FirstArg,
          LockingSemanticsKind::PthreadSemantics},
      EventDescriptor{CallDescription{CDM::CLibrary, {"lck_mtx_try_lock"}, 1},
                      EventKind::TryAcquire, SyntaxKind::FirstArg,
                      LockingSemanticsKind::XNUSemantics},
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"lck_rw_try_lock_exclusive"}, 1},
          EventKind::TryAcquire, SyntaxKind::FirstArg,
          LockingSemanticsKind::XNUSemantics},
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"lck_rw_try_lock_shared"}, 1},
          EventKind::TryAcquire, SyntaxKind::FirstArg,
          LockingSemanticsKind::XNUSemantics},

      // - Fuchsia
      EventDescriptor{CallDescription{CDM::CLibrary, {"spin_trylock"}, 1},
                      EventKind::TryAcquire, SyntaxKind::FirstArg,
                      LockingSemanticsKind::PthreadSemantics},
      EventDescriptor{CallDescription{CDM::CLibrary, {"sync_mutex_trylock"}, 1},
                      EventKind::TryAcquire, SyntaxKind::FirstArg,
                      LockingSemanticsKind::PthreadSemantics},
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"sync_mutex_timedlock"}, 2},
          EventKind::TryAcquire, SyntaxKind::FirstArg,
          LockingSemanticsKind::PthreadSemantics},

      // - C11
      EventDescriptor{CallDescription{CDM::CLibrary, {"mtx_trylock"}, 1},
                      EventKind::TryAcquire, SyntaxKind::FirstArg,
                      LockingSemanticsKind::PthreadSemantics},
      EventDescriptor{CallDescription{CDM::CLibrary, {"mtx_timedlock"}, 2},
                      EventKind::TryAcquire, SyntaxKind::FirstArg,
                      LockingSemanticsKind::PthreadSemantics},

      // Release kind
      // - Pthread
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"pthread_mutex_unlock"}, 1},
          EventKind::Release, SyntaxKind::FirstArg,
          LockingSemanticsKind::NotApplicable},
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"pthread_rwlock_unlock"}, 1},
          EventKind::Release, SyntaxKind::FirstArg,
          LockingSemanticsKind::NotApplicable},
      EventDescriptor{CallDescription{CDM::CLibrary, {"lck_mtx_unlock"}, 1},
                      EventKind::Release, SyntaxKind::FirstArg,
                      LockingSemanticsKind::NotApplicable},
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"lck_rw_unlock_exclusive"}, 1},
          EventKind::Release, SyntaxKind::FirstArg,
          LockingSemanticsKind::NotApplicable},
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"lck_rw_unlock_shared"}, 1},
          EventKind::Release, SyntaxKind::FirstArg,
          LockingSemanticsKind::NotApplicable},
      EventDescriptor{CallDescription{CDM::CLibrary, {"lck_rw_done"}, 1},
                      EventKind::Release, SyntaxKind::FirstArg,
                      LockingSemanticsKind::NotApplicable},

      // - Fuchsia
      EventDescriptor{CallDescription{CDM::CLibrary, {"spin_unlock"}, 1},
                      EventKind::Release, SyntaxKind::FirstArg,
                      LockingSemanticsKind::NotApplicable},
      EventDescriptor{
          CallDescription{CDM::CLibrary, {"spin_unlock_restore"}, 3},
          EventKind::Release, SyntaxKind::FirstArg,
          LockingSemanticsKind::NotApplicable},
      EventDescriptor{CallDescription{CDM::CLibrary, {"sync_mutex_unlock"}, 1},
                      EventKind::Release, SyntaxKind::FirstArg,
                      LockingSemanticsKind::NotApplicable},

      // - C11
      EventDescriptor{CallDescription{CDM::CLibrary, {"mtx_unlock"}, 1},
                      EventKind::Release, SyntaxKind::FirstArg,
                      LockingSemanticsKind::NotApplicable},

      // - std
      EventDescriptor{
          CallDescription{CDM::CXXMethod, {"std", "mutex", "unlock"}, 0},
          EventKind::Release, SyntaxKind::Member,
          LockingSemanticsKind::NotApplicable},

      // Destroy kind
      // - Pthread
      EventDescriptor{{CDM::CLibrary, {"pthread_mutex_destroy"}, 1},
                      EventKind::Destroy,
                      SyntaxKind::FirstArg,
                      LockingSemanticsKind::NotApplicable},
      EventDescriptor{CallDescription{CDM::CLibrary, {"lck_mtx_destroy"}, 2},
                      EventKind::Destroy, SyntaxKind::FirstArg,
                      LockingSemanticsKind::NotApplicable},
      // TODO: pthread_rwlock_destroy(1 argument).
      // TODO: lck_rw_destroy(2 arguments).

      // - C11
      EventDescriptor{CallDescription{CDM::CLibrary, {"mtx_destroy"}, 1},
                      EventKind::Destroy, SyntaxKind::FirstArg,
                      LockingSemanticsKind::NotApplicable}};

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};

static void updateCritSectionOnLock(const MutexDescriptor &LockDescriptor,
                                    const CallEvent &Call,
                                    CheckerContext &C) const {
  const MemRegion *MutexRegion =
      getRegion(Call, LockDescriptor, /*IsLock=*/true);
  if (!MutexRegion)
    return;

  const CritSectionMarker MarkToAdd{Call.getOriginExpr(), MutexRegion};
  ProgramStateRef StateWithLockEvent =
      C.getState()->add<CritSections>(MarkToAdd);
  C.addTransition(StateWithLockEvent, CreateMutexCritSectionNote(MarkToAdd, C));
}

static void
updateCriticalSectionOnUnlock(const MutexDescriptor &UnlockDescriptor,
                              const CallEvent &Call, CheckerContext &C) const {
  const MemRegion *MutexRegion =
      getRegion(Call, UnlockDescriptor, /*IsLock=*/false);
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

  State = State->set<CritSections>(NewList);
  C.addTransition(State);
}

std::optional<MutexDescriptor> MutexModeling::checkDescriptorMatch(
    const CallEvent &Call, CheckerContext &C,
    const llvm::SmallVectorImpl<EventDescriptor> &Events) {}
std::optional<MutexDescriptor> Descriptor;
const auto DescriptorIt =
    llvm::find_if(MutexDescriptors, [&Call, IsLock](auto &&Descriptor) {
      return std::visit(
          [&Call, IsLock](auto &&DescriptorImpl) {
            return DescriptorImpl.matches(Call, IsLock);
          },
          Descriptor);
    });
if (DescriptorIt != MutexDescriptors.end())
  Descriptor.emplace(*DescriptorIt);
return Descriptor;
} // namespace

staic void handleInit(const EventDescriptor &Event, const CallEvent &Call,
                      CheckerContext &C) {}

static void getTriggerExpr(const EventDescriptor &Event, const CallEvent &Call,
                           CheckerContext &C) {
  switch (Event.Syntax) {
  case Syntax::FirstArg:
    break;
  case Syntax::Member:
    break;
  case Syntax::RAII:
    break;
  }
}

static void getMutexRegion(const EventDescriptor &Event, const CallEvent &Call,
                           CheckerContext &C) {
  switch (Event.Syntax) {
  case Syntax::FirstArg:
    break;
  case Syntax::Member:
    break;
  case Syntax::RAII:
    break;
  }
}

staic void handleInit(const EventDescriptor &Event, const CallEvent &Call, CheckerContext &C) {
  const auto *MTX = getMutexRegion(Event, Call, C);
  if (!MTX)
    return;

  ProgramStateRef State = C.getState();

  const SymbolRef *Sym = State->get<DestroyRetVal>(MTX);
  if (Sym)
    State = resolvePossiblyDestroyedMutex(State, MTX, sym);

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


static void handleEvent(const EventDescriptor &Event, const CallEvent &Call,
                        CheckerContext &C) {
  switch (Event.Kind) {
  case Event::Init:
    handleInit(Event, Call, C);
    break;
  case Event::Acquire:
    handleAcquire(Event, Call, C);
    break;
  case Event::TryAcquire:
    handleTryAcquire(Event, Call, C);
    break;
  case Event::Release:
    handleRelease(Event, Call, C);
    break;
  case Event::Destroy:
    handleDestroy(Event, Call, C);
    break;
  }
}

void MutexModeling::checkPostCall(const CallEvent &Call,
                                  CheckerContext &C) const {
  for (auto &&Event : HandledEvents) {
    if (Event.Trigger.matches(Call)) {
      handleEvent(Event, Call, C);
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
