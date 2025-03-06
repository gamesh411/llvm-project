//===-- BlockInCriticalSectionChecker.cpp -----------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Defines a checker for blocks in critical sections. This checker should find
// the calls to blocking functions (for example: sleep, getc, fgets, read,
// recv etc.) inside a critical section. When sleep(x) is called while a mutex
// is held, other threades cannot lock the same mutex. This might take some
// time, leading to bad performance or even deadlock.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Checkers/MutexModeling.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringExtras.h"

#include <iterator>
#include <utility>
#include <variant>

using namespace clang;
using namespace ento;

namespace {

// Using the types defined in MutexModeling.h

class SuppressNonBlockingStreams : public BugReporterVisitor {
private:
  const CallDescription OpenFunction{CDM::CLibrary, {"open"}, 2};
  SymbolRef StreamSym;
  const int NonBlockMacroVal;
  bool Satisfied = false;

public:
  SuppressNonBlockingStreams(SymbolRef StreamSym, int NonBlockMacroVal)
      : StreamSym(StreamSym), NonBlockMacroVal(NonBlockMacroVal) {}

  static void *getTag() {
    static bool Tag;
    return &Tag;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const override {
    ID.AddPointer(getTag());
  }

  PathDiagnosticPieceRef VisitNode(const ExplodedNode *N,
                                   BugReporterContext &BRC,
                                   PathSensitiveBugReport &BR) override {
    if (Satisfied)
      return nullptr;

    std::optional<StmtPoint> Point = N->getLocationAs<StmtPoint>();
    if (!Point)
      return nullptr;

    const auto *CE = Point->getStmtAs<CallExpr>();
    if (!CE || !OpenFunction.matchesAsWritten(*CE))
      return nullptr;

    if (N->getSVal(CE).getAsSymbol() != StreamSym)
      return nullptr;

    Satisfied = true;

    // Check if open's second argument contains O_NONBLOCK
    const llvm::APSInt *FlagVal = N->getSVal(CE->getArg(1)).getAsInteger();
    if (!FlagVal)
      return nullptr;

    if ((*FlagVal & NonBlockMacroVal) != 0)
      BR.markInvalid(getTag(), nullptr);

    return nullptr;
  }
};

class BlockInCriticalSectionChecker : public Checker<check::PostCall> {
private:
  const std::array<MutexDescriptor, 8> MutexDescriptors{
      // NOTE: There are standard library implementations where some methods
      // of `std::mutex` are inherited from an implementation detail base
      // class, and those aren't matched by the name specification {"std",
      // "mutex", "lock"}.
      // As a workaround here we omit the class name and only require the
      // presence of the name parts "std" and "lock"/"unlock".
      // TODO: Ensure that CallDescription understands inherited methods.
      MemberMutexDescriptor(
          {/*MatchAs=*/CDM::CXXMethod,
           /*QualifiedName=*/{"std", /*"mutex",*/ "lock"},
           /*RequiredArgs=*/0},
          {CDM::CXXMethod, {"std", /*"mutex",*/ "unlock"}, 0}),
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

  const CallDescriptionSet BlockingFunctions{{CDM::CLibrary, {"sleep"}},
                                             {CDM::CLibrary, {"getc"}},
                                             {CDM::CLibrary, {"fgets"}},
                                             {CDM::CLibrary, {"read"}},
                                             {CDM::CLibrary, {"recv"}}};

  const BugType BlockInCritSectionBugType{
      this, "Call to blocking function in critical section", "Blocking Error"};

  using O_NONBLOCKValueTy = std::optional<int>;
  mutable std::optional<O_NONBLOCKValueTy> O_NONBLOCKValue;

  void reportBlockInCritSection(const CallEvent &call, CheckerContext &C) const;

  [[nodiscard]] const NoteTag *createCritSectionNote(CritSectionMarker M,
                                                     CheckerContext &C) const;

  [[nodiscard]] std::optional<MutexDescriptor>
  checkDescriptorMatch(const CallEvent &Call, CheckerContext &C,
                       bool IsLock) const;

  void handleLock(const MutexDescriptor &Mutex, const CallEvent &Call,
                  CheckerContext &C) const;

  void handleUnlock(const MutexDescriptor &Mutex, const CallEvent &Call,
                    CheckerContext &C) const;

  [[nodiscard]] bool isBlockingInCritSection(const CallEvent &Call,
                                             CheckerContext &C) const;

public:
  /// Process unlock.
  /// Process lock.
  /// Process blocking functions (sleep, getc, fgets, read, recv)
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

REGISTER_LIST_WITH_PROGRAMSTATE(ActiveCritSections,
                                clang::ento::CritSectionMarker)

std::optional<MutexDescriptor>
BlockInCriticalSectionChecker::checkDescriptorMatch(const CallEvent &Call,
                                                    CheckerContext &C,
                                                    bool IsLock) const {
  const auto Descriptor =
      llvm::find_if(MutexDescriptors, [&Call, IsLock](auto &&Descriptor) {
        return std::visit(
            [&Call, IsLock](auto &&DescriptorImpl) {
              return DescriptorImpl.matches(Call, IsLock);
            },
            Descriptor);
      });
  if (Descriptor != MutexDescriptors.end())
    return *Descriptor;
  return std::nullopt;
}

static const MemRegion *skipStdBaseClassRegion(const MemRegion *Reg) {
  while (Reg) {
    const auto *BaseClassRegion = dyn_cast<CXXBaseObjectRegion>(Reg);
    if (!BaseClassRegion || !isWithinStdNamespace(BaseClassRegion->getDecl()))
      break;
    Reg = BaseClassRegion->getSuperRegion();
  }
  return Reg;
}

static const MemRegion *getRegion(const CallEvent &Call,
                                  const MutexDescriptor &Descriptor,
                                  bool IsLock) {
  return std::visit(
      [&Call, IsLock](auto &Descr) -> const MemRegion * {
        return skipStdBaseClassRegion(Descr.getRegion(Call, IsLock));
      },
      Descriptor);
}

void BlockInCriticalSectionChecker::handleLock(
    const MutexDescriptor &LockDescriptor, const CallEvent &Call,
    CheckerContext &C) const {
  const MemRegion *MutexRegion =
      getRegion(Call, LockDescriptor, /*IsLock=*/true);
  if (!MutexRegion)
    return;

  const CritSectionMarker MarkToAdd{Call.getOriginExpr(), MutexRegion};
  ProgramStateRef StateWithLockEvent =
      C.getState()->add<ActiveCritSections>(MarkToAdd);
  C.addTransition(StateWithLockEvent, createCritSectionNote(MarkToAdd, C));
}

void BlockInCriticalSectionChecker::handleUnlock(
    const MutexDescriptor &UnlockDescriptor, const CallEvent &Call,
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
  for (auto It = ActiveSections.begin(), End = ActiveSections.end(); It != End;
       ++It) {
    if (It != MostRecentLock)
      NewList = Factory.add(*It, NewList);
  }

  State = State->set<ActiveCritSections>(NewList);
  C.addTransition(State);
}

bool BlockInCriticalSectionChecker::isBlockingInCritSection(
    const CallEvent &Call, CheckerContext &C) const {
  return BlockingFunctions.contains(Call) &&
         !C.getState()->get<ActiveCritSections>().isEmpty();
}

void BlockInCriticalSectionChecker::checkPostCall(const CallEvent &Call,
                                                  CheckerContext &C) const {
  if (isBlockingInCritSection(Call, C)) {
    reportBlockInCritSection(Call, C);
  } else if (std::optional<MutexDescriptor> LockDesc =
                 checkDescriptorMatch(Call, C, /*IsLock=*/true)) {
    handleLock(*LockDesc, Call, C);
  } else if (std::optional<MutexDescriptor> UnlockDesc =
                 checkDescriptorMatch(Call, C, /*IsLock=*/false)) {
    handleUnlock(*UnlockDesc, Call, C);
  }
}

void BlockInCriticalSectionChecker::reportBlockInCritSection(
    const CallEvent &Call, CheckerContext &C) const {
  ExplodedNode *ErrNode = C.generateNonFatalErrorNode(C.getState());
  if (!ErrNode)
    return;

  std::string msg;
  llvm::raw_string_ostream os(msg);
  os << "Call to blocking function '" << Call.getCalleeIdentifier()->getName()
     << "' inside of critical section";
  auto R = std::make_unique<PathSensitiveBugReport>(BlockInCritSectionBugType,
                                                    os.str(), ErrNode);
  // for 'read' and 'recv' call, check whether it's file descriptor(first
  // argument) is
  // created by 'open' API with O_NONBLOCK flag or is equal to -1, they will
  // not cause block in these situations, don't report
  StringRef FuncName = Call.getCalleeIdentifier()->getName();
  if (FuncName == "read" || FuncName == "recv") {
    SVal SV = Call.getArgSVal(0);
    SValBuilder &SVB = C.getSValBuilder();
    ProgramStateRef state = C.getState();
    ConditionTruthVal CTV =
        state->areEqual(SV, SVB.makeIntVal(-1, C.getASTContext().IntTy));
    if (CTV.isConstrainedTrue())
      return;

    if (SymbolRef SR = SV.getAsSymbol()) {
      if (!O_NONBLOCKValue)
        O_NONBLOCKValue = tryExpandAsInteger(
            "O_NONBLOCK", C.getBugReporter().getPreprocessor());
      if (*O_NONBLOCKValue)
        R->addVisitor<SuppressNonBlockingStreams>(SR, **O_NONBLOCKValue);
    }
  }
  R->addRange(Call.getSourceRange());
  R->markInteresting(Call.getReturnValue());
  C.emitReport(std::move(R));
}

const NoteTag *
BlockInCriticalSectionChecker::createCritSectionNote(CritSectionMarker M,
                                                     CheckerContext &C) const {
  const BugType *BT = &this->BlockInCritSectionBugType;
  return C.getNoteTag([M, BT](PathSensitiveBugReport &BR,
                              llvm::raw_ostream &OS) {
    if (&BR.getBugType() != BT)
      return;

    // Get the lock events for the mutex of the current line's lock event.
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
    const auto Position =
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

void ento::registerBlockInCriticalSectionChecker(CheckerManager &mgr) {
  mgr.registerChecker<BlockInCriticalSectionChecker>();
}

bool ento::shouldRegisterBlockInCriticalSectionChecker(
    const CheckerManager &mgr) {
  return true;
}
