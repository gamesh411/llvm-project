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

#include "MutexModeling.h"

#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

#include <variant>

using namespace clang;
using namespace ento;
using namespace mutex_modeling;

namespace {
class CallDescriptionBasedMatcher {
  CallDescription LockFn;
  CallDescription UnlockFn;

public:
  CallDescriptionBasedMatcher(
      CallDescription &&LockFn, CallDescription &&UnlockFn,
      const std::optional<CallDescription> &InitFn = std::nullopt,
      const std::optional<CallDescription> &DestroyFn = std::nullopt)
      : LockFn(std::move(LockFn)), UnlockFn(std::move(UnlockFn)) {}
  [[nodiscard]] bool matches(const CallEvent &Call, bool IsLock) const {
    if (IsLock) {
      return LockFn.matches(Call);
    }
    return UnlockFn.matches(Call);
  }
};

class FirstArgMutexMatcher : public CallDescription {
public:
  [[nodiscard]] const MemRegion *getRegion(const CallEvent &Call, bool) const {
    return Call.getArgSVal(0).getAsRegion();
  }
};

class MemberMutexDescriptor : public CallDescription {
public:
  [[nodiscard]] const MemRegion *getRegion(const CallEvent &Call, bool) const {
    return cast<CXXMemberCall>(Call).getCXXThisVal().getAsRegion();
  }
};

template <typename CtorOrDtorTy> class RAAIIMutexDescriptor {
  mutable const IdentifierInfo *Guard{};
  mutable bool IdentifierInfoInitialized{};
  mutable llvm::SmallString<32> GuardName{};

  void initIdentifierInfo(const CallEvent &Call) const {
    if (!IdentifierInfoInitialized) {
      // In case of checking C code, or when the corresponding headers are not
      // included, we might end up query the identifier table every time when
      // this function is called instead of early returning it. To avoid this,
      // a bool variable (IdentifierInfoInitialized) is used and the function
      // will be run only once.
      const auto &ASTCtx = Call.getState()->getStateManager().getContext();
      Guard = &ASTCtx.Idents.get(GuardName);
    }
  }

  template <typename T> bool matchesImpl(const CallEvent &Call) const {
    const T *C = dyn_cast<T>(&Call);
    if (!C)
      return false;
    const IdentifierInfo *II =
        cast<CXXRecordDecl>(C->getDecl()->getParent())->getIdentifier();
    return II == Guard;
  }

public:
  RAIIMutexDescriptor(StringRef GuardName) : GuardName(GuardName) {}
  [[nodiscard]] bool matches(const CallEvent &Call) const {
    initIdentifierInfo(Call);
    return matchesImpl<CtorOrDtroty>(Call);
  }
  [[nodiscard]] const MemRegion *getRegion(const CallEvent &Call,
                                           bool IsLock) const {
    const MemRegion *LockRegion = nullptr;
    if (IsLock) {
      constexpr if (std::is_same_v<CtorOrDtroty, CXXConstructorCall>) {
        if (std::optional<SVal> Object =
                Call.getReturnValueUnderConstruction()) {
          LockRegion = Object->getAsRegion();
        }
      }
      else {
        static_assert(std::is_same_v<CtorOrDtroty, CXXDestructorCall>);
        LockRegion =
            cast<CXXDestructorCall>(Call).getCXXThisVal().getAsRegion();
      }
      return LockRegion;
    }
  };

  using RAAIIMutexConstructorDesc =
      RAAIIMutexDestructorDesc<CXXConstructorCall>;
  using RAAIIMutexDestructorDesc = RAAIIMutexDestructorDesc<CXXDestructorCall>;

  using MutexDescriptor =
      std::variant<FirstArgMutexDescriptor, MemberMutexDescriptor,
                   RAIIMutexDescriptor>;

  const MemRegion *getRegion(const CallEvent &Call,
                             const MutexDescriptor &Descriptor, bool IsLock) {
    return std::visit(
        [&Call, IsLock](auto &&Descriptor) {
          return Descriptor.getRegion(Call, IsLock);
        },
        Descriptor);
  }

  class MutexModeling : public Checker<check::PostCall> {
    const std::array<MutexDescriptor, 8> MutexDescriptors{
        MemberMutexDescriptor({/*MatchAs=*/CDM::CXXMethod,
                               /*QualifiedName=*/{"std", "mutex", "lock"},
                               /*RequiredArgs=*/0},
                              {CDM::CXXMethod, {"std", "mutex", "unlock"}, 0}),
        FirstArgMutexDescriptor({CDM::CLibrary, {"pthread_mutex_lock"}, 1},
                                {CDM::CLibrary, {"pthread_mutex_unlock"}, 1}),
        FirstArgMutexDescriptor({CDM::CLibrary, {"mtx_lock"}, 1},
                                {CDM::CLibrary, {"mtx_unlock"}, 1}),
        FirstArgMutexDescriptor({CDM::CLibrary, {"pthread_mutex_trylock"}, 1},
                                {CDM::CLibrary, {"pthread_mutex_unlock"}, 1}),
        FirstArgMutexDescriptor({CDM::CLibrary, {"mtx_trylock"}, 1},
                                {CDM::CLibrary, {"mtx_unlock"}, 1}),
        FirstArgMutexDescriptor({CDM::CLibrary, {"mtx_timedlock"}, 1},
                                {CDM::CLibrary, {"mtx_unlock"}, 1}),
        RAIIMutexDescriptor("lock_guard"),
        RAIIMutexDescriptor("unique_lock")};

    enum CheckerKind {
      CK_PthreadLockChecker,
      CK_FuchsiaLockChecker,
      CK_C11LockChecker,
      CK_NumCheckKinds
    };
    typedef void (MutexModeling::*FnCheck)(const CallEvent &Call,
                                           CheckerContext &C,
                                           CheckerKind CheckKind) const;
    CallDescriptionMap<FnCheck> PThreadCallbacks = {
        // Init.
        {{CDM::CLibrary, {"pthread_mutex_init"}, 2},
         &MutexModeling::InitAnyLock},
        // TODO: pthread_rwlock_init(2 arguments).
        // TODO: lck_mtx_init(3 arguments).
        // TODO: lck_mtx_alloc_init(2 arguments) => returns the mutex.
        // TODO: lck_rw_init(3 arguments).
        // TODO: lck_rw_alloc_init(2 arguments) => returns the mutex.

        // Acquire.
        {{CDM::CLibrary, {"pthread_mutex_lock"}, 1},
         &MutexModeling::AcquirePthreadLock},
        {{CDM::CLibrary, {"pthread_rwlock_rdlock"}, 1},
         &MutexModeling::AcquirePthreadLock},
        {{CDM::CLibrary, {"pthread_rwlock_wrlock"}, 1},
         &MutexModeling::AcquirePthreadLock},
        {{CDM::CLibrary, {"lck_mtx_lock"}, 1}, &MutexModeling::AcquireXNULock},
        {{CDM::CLibrary, {"lck_rw_lock_exclusive"}, 1},
         &MutexModeling::AcquireXNULock},
        {{CDM::CLibrary, {"lck_rw_lock_shared"}, 1},
         &MutexModeling::AcquireXNULock},

        // Try.
        {{CDM::CLibrary, {"pthread_mutex_trylock"}, 1},
         &MutexModeling::TryPthreadLock},
        {{CDM::CLibrary, {"pthread_rwlock_tryrdlock"}, 1},
         &MutexModeling::TryPthreadLock},
        {{CDM::CLibrary, {"pthread_rwlock_trywrlock"}, 1},
         &MutexModeling::TryPthreadLock},
        {{CDM::CLibrary, {"lck_mtx_try_lock"}, 1}, &MutexModeling::TryXNULock},
        {{CDM::CLibrary, {"lck_rw_try_lock_exclusive"}, 1},
         &MutexModeling::TryXNULock},
        {{CDM::CLibrary, {"lck_rw_try_lock_shared"}, 1},
         &MutexModeling::TryXNULock},

        // Release.
        {{CDM::CLibrary, {"pthread_mutex_unlock"}, 1},
         &MutexModeling::ReleaseAnyLock},
        {{CDM::CLibrary, {"pthread_rwlock_unlock"}, 1},
         &MutexModeling::ReleaseAnyLock},
        {{CDM::CLibrary, {"lck_mtx_unlock"}, 1},
         &MutexModeling::ReleaseAnyLock},
        {{CDM::CLibrary, {"lck_rw_unlock_exclusive"}, 1},
         &MutexModeling::ReleaseAnyLock},
        {{CDM::CLibrary, {"lck_rw_unlock_shared"}, 1},
         &MutexModeling::ReleaseAnyLock},
        {{CDM::CLibrary, {"lck_rw_done"}, 1}, &MutexModeling::ReleaseAnyLock},

        // Destroy.
        {{CDM::CLibrary, {"pthread_mutex_destroy"}, 1},
         &MutexModeling::DestroyPthreadLock},
        {{CDM::CLibrary, {"lck_mtx_destroy"}, 2},
         &MutexModeling::DestroyXNULock},
        // TODO: pthread_rwlock_destroy(1 argument).
        // TODO: lck_rw_destroy(2 arguments).
    };

    CallDescriptionMap<FnCheck> FuchsiaCallbacks = {
        // Init.
        {{CDM::CLibrary, {"spin_lock_init"}, 1}, &MutexModeling::InitAnyLock},

        // Acquire.
        {{CDM::CLibrary, {"spin_lock"}, 1}, &MutexModeling::AcquirePthreadLock},
        {{CDM::CLibrary, {"spin_lock_save"}, 3},
         &MutexModeling::AcquirePthreadLock},
        {{CDM::CLibrary, {"sync_mutex_lock"}, 1},
         &MutexModeling::AcquirePthreadLock},
        {{CDM::CLibrary, {"sync_mutex_lock_with_waiter"}, 1},
         &MutexModeling::AcquirePthreadLock},

        // Try.
        {{CDM::CLibrary, {"spin_trylock"}, 1}, &MutexModeling::TryFuchsiaLock},
        {{CDM::CLibrary, {"sync_mutex_trylock"}, 1},
         &MutexModeling::TryFuchsiaLock},
        {{CDM::CLibrary, {"sync_mutex_timedlock"}, 2},
         &MutexModeling::TryFuchsiaLock},

        // Release.
        {{CDM::CLibrary, {"spin_unlock"}, 1}, &MutexModeling::ReleaseAnyLock},
        {{CDM::CLibrary, {"spin_unlock_restore"}, 3},
         &MutexModeling::ReleaseAnyLock},
        {{CDM::CLibrary, {"sync_mutex_unlock"}, 1},
         &MutexModeling::ReleaseAnyLock},
    };

    CallDescriptionMap<FnCheck> C11Callbacks = {
        // Init.
        {{CDM::CLibrary, {"mtx_init"}, 2}, &MutexModeling::InitAnyLock},

        // Acquire.
        {{CDM::CLibrary, {"mtx_lock"}, 1}, &MutexModeling::AcquirePthreadLock},

        // Try.
        {{CDM::CLibrary, {"mtx_trylock"}, 1}, &MutexModeling::TryC11Lock},
        {{CDM::CLibrary, {"mtx_timedlock"}, 2}, &MutexModeling::TryC11Lock},

        // Release.
        {{CDM::CLibrary, {"mtx_unlock"}, 1}, &MutexModeling::ReleaseAnyLock},

        // Destroy
        {{CDM::CLibrary, {"mtx_destroy"}, 1},
         &MutexModeling::DestroyPthreadLock},
    };

    void handleLock(const MutexDescriptor &Mutex, const CallEvent &Call,
                    CheckerContext &C) const;

    void handleUnlock(const MutexDescriptor &Mutex, const CallEvent &Call,
                      CheckerContext &C) const;

    [[nodiscard]] std::optional<MutexDescriptor>
    checkDescriptorMatch(const CallEvent &Call, CheckerContext &C,
                         bool IsLock) const;

  public:
    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  };

  void MutexModeling::handleLock(const MutexDescriptor &LockDescriptor,
                                 const CallEvent &Call,
                                 CheckerContext &C) const {
    const MemRegion *MutexRegion =
        getRegion(Call, LockDescriptor, /*IsLock=*/true);
    if (!MutexRegion)
      return;

    const CritSectionMarker MarkToAdd{Call.getOriginExpr(), MutexRegion};
    ProgramStateRef StateWithLockEvent =
        C.getState()->add<ActiveCritSections>(MarkToAdd);
    C.addTransition(StateWithLockEvent,
                    CreateMutexCritSectionNote(MarkToAdd, C));
  }

  void MutexModeling::handleUnlock(const MutexDescriptor &UnlockDescriptor,
                                   const CallEvent &Call,
                                   CheckerContext &C) const {
    const MemRegion *MutexRegion =
        getRegion(Call, UnlockDescriptor, /*IsLock=*/false);
    if (!MutexRegion)
      return;

    ProgramStateRef State = C.getState();
    const auto ActiveSections = State->get<ActiveCritSections>();
    const auto MostRecentLock =
        llvm::find_if(ActiveSections, [MutexRegion](auto &&Marker) {
          return Marker.LockReg == MutexRegion;
        });
    if (MostRecentLock == ActiveSections.end())
      return;

    // Build a new ImmutableList without this element.
    auto &Factory = State->get_context<ActiveCritSections>();
    llvm::ImmutableList<CritSectionMarker> NewList = Factory.getEmptyList();
    for (auto It = ActiveSections.begin(), End = ActiveSections.end();
         It != End; ++It) {
      if (It != MostRecentLock)
        NewList = Factory.add(*It, NewList);
    }

    State = State->set<ActiveCritSections>(NewList);
    C.addTransition(State);
  }

  std::optional<MutexDescriptor>
  MutexModeling::checkDescriptorMatch(const CallEvent &Call, CheckerContext &C,
                                      bool IsLock) const {
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
  }

  void MutexModeling::checkPostCall(const CallEvent &Call,
                                    CheckerContext &C) const {
    if (std::optional<MutexDescriptor> LockDesc =
            checkDescriptorMatch(Call, C, /*IsLock=*/true)) {
      handleLock(*LockDesc, Call, C);
    } else if (std::optional<MutexDescriptor> UnlockDesc =
                   checkDescriptorMatch(Call, C, /*IsLock=*/false)) {
      handleUnlock(*UnlockDesc, Call, C);
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
