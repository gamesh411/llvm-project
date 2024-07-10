#ifndef CALLDESCRIPTIONBASEDMATCHER_H
#define CALLDESCRIPTIONBASEDMATCHER_H

// TODO: eliminiate this file

#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include <variant>

class CallDescriptionBasedMatcher {
  clang::ento::CallDescription LockFn;
  clang::ento::CallDescription UnlockFn;

public:
  CallDescriptionBasedMatcher(clang::ento::CallDescription &&LockFn,
                              clang::ento::CallDescription &&UnlockFn)
      : LockFn(std::move(LockFn)), UnlockFn(std::move(UnlockFn)) {}
  [[nodiscard]] bool matches(const clang::ento::CallEvent &Call,
                             bool IsLock) const {
    if (IsLock) {
      return LockFn.matches(Call);
    }
    return UnlockFn.matches(Call);
  }
};

class FirstArgMutexDescriptor : public CallDescriptionBasedMatcher {
public:
  FirstArgMutexDescriptor(clang::ento::CallDescription &&LockFn,
                          clang::ento::CallDescription &&UnlockFn)
      : CallDescriptionBasedMatcher(std::move(LockFn), std::move(UnlockFn)) {}

  [[nodiscard]] const clang::ento::MemRegion *
  getRegion(const clang::ento::CallEvent &Call, bool) const {
    return Call.getArgSVal(0).getAsRegion();
  }
};

class MemberMutexDescriptor : public CallDescriptionBasedMatcher {
public:
  MemberMutexDescriptor(clang::ento::CallDescription &&LockFn,
                        clang::ento::CallDescription &&UnlockFn)
      : CallDescriptionBasedMatcher(std::move(LockFn), std::move(UnlockFn)) {}

  [[nodiscard]] const clang::ento::MemRegion *
  getRegion(const clang::ento::CallEvent &Call, bool) const {
    return llvm::cast<clang::ento::CXXMemberCall>(Call).getCXXThisVal().getAsRegion();
  }
};

class RAIIMutexDescriptor {
  mutable const clang::IdentifierInfo *Guard{};
  mutable bool IdentifierInfoInitialized{};
  mutable llvm::SmallString<32> GuardName{};

  void initIdentifierInfo(const clang::ento::CallEvent &Call) const {
    if (!IdentifierInfoInitialized) {
      // In case of checking C code, or when the corresponding headers are not
      // included, we might end up query the identifier table every time when
      // this function is called instead of early returning it. To avoid this, a
      // bool variable (IdentifierInfoInitialized) is used and the function will
      // be run only once.
      const auto &ASTCtx = Call.getState()->getStateManager().getContext();
      Guard = &ASTCtx.Idents.get(GuardName);
    }
  }

  template <typename T>
  bool matchesImpl(const clang::ento::CallEvent &Call) const {
    const T *C = llvm::dyn_cast<T>(&Call);
    if (!C)
      return false;
    const clang::IdentifierInfo *II =
        llvm::cast<clang::CXXRecordDecl>(C->getDecl()->getParent())->getIdentifier();
    return II == Guard;
  }

public:
  RAIIMutexDescriptor(llvm::StringRef GuardName) : GuardName(GuardName) {}
  [[nodiscard]] bool matches(const clang::ento::CallEvent &Call,
                             bool IsLock) const {
    initIdentifierInfo(Call);
    if (IsLock) {
      return matchesImpl<clang::ento::CXXConstructorCall>(Call);
    }
    return matchesImpl<clang::ento::CXXDestructorCall>(Call);
  }
  [[nodiscard]] const clang::ento::MemRegion *
  getRegion(const clang::ento::CallEvent &Call, bool IsLock) const {
    const clang::ento::MemRegion *MutexRegion = nullptr;
    if (IsLock) {
      if (std::optional<clang::ento::SVal> Object = Call.getReturnValueUnderConstruction()) {
        MutexRegion = Object->getAsRegion();
      }
    } else {
      MutexRegion = cast<CXXDestructorCall>(Call).getCXXThisVal().getAsRegion();
    }
    return MutexRegion;
  }
};

using MutexDescriptor =
    std::variant<FirstArgMutexDescriptor, MemberMutexDescriptor,
                 RAIIMutexDescriptor>;

const clang::ento::MemRegion *getRegion(const clang::ento::CallEvent &Call,
                                        const MutexDescriptor &Descriptor,
                                        bool IsLock) {
  return std::visit(
      [&Call, IsLock](auto &&Descriptor) {
        return Descriptor.getRegion(Call, IsLock);
      },
      Descriptor);
}

#endif
