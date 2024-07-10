//===--- MutexModelingGDM.h - Modeling of mutexes in GDM ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Defines the GDM definitions for tracking mutex states.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_MUTEXMODELINGGDM_H
#define LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_MUTEXMODELINGGDM_H

#include "MutexModelingDomain.h"

#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "llvm/ADT/FoldingSet.h"

// GDM-related handle-types for tracking mutex states.
namespace clang {
namespace ento {
namespace mutex_modeling {

class MutexEvents {};
using MutexEventsTy = llvm::ImmutableList<EventMarker>;

class CritSections {};
using CritSectionsTy = llvm::ImmutableList<CritSectionMarker>;

class LockStates {};
using LockStatesTy = llvm::ImmutableMap<const MemRegion*, LockState>;

class DestroyedRetVals {};
using DestroyedRetValsTy = llvm::ImmutableMap<const MemRegion*, SymbolRef>;

} // namespace mutex_modeling
} // namespace ento
} // namespace clang

// Enable usage of mutex modeling data structures in llvm::FoldingSet.
namespace llvm {
template <> struct FoldingSetTrait<clang::ento::mutex_modeling::EventMarker> {
  static void Profile(const clang::ento::mutex_modeling::EventMarker &EM,
               llvm::FoldingSetNodeID &ID) {
    ID.Add(EM.Event.Kind);
    ID.Add(EM.Event.Syntax);
    ID.Add(EM.Event.Semantics);
    ID.Add(EM.LockState);
    ID.Add(EM.EventExpr);
    ID.Add(EM.MutexRegion);
  }
};

template <>
struct FoldingSetTrait<clang::ento::mutex_modeling::CritSectionMarker> {
  static void Profile(const clang::ento::mutex_modeling::CritSectionMarker &CSM,
               llvm::FoldingSetNodeID &ID) {
    ID.Add(CSM.BeginExpr);
    ID.Add(CSM.MutexRegion);
  }
};
} // namespace llvm

// Iterator traits for ImmutableList data structure
// that enable the use of STL algorithms.
namespace std {
// TODO: Move these to llvm::ImmutableList when overhauling immutable data
// structures for proper iterator concept support.
template <>
struct iterator_traits<typename llvm::ImmutableList<
    clang::ento::mutex_modeling::EventMarker>::iterator> {
  using iterator_category = std::forward_iterator_tag;
  using value_type = clang::ento::mutex_modeling::EventMarker;
  using difference_type = std::ptrdiff_t;
  using reference = clang::ento::mutex_modeling::EventMarker &;
  using pointer = clang::ento::mutex_modeling::EventMarker *;
};
template <>
struct iterator_traits<typename llvm::ImmutableList<
    clang::ento::mutex_modeling::CritSectionMarker>::iterator> {
  using iterator_category = std::forward_iterator_tag;
  using value_type = clang::ento::mutex_modeling::CritSectionMarker;
  using difference_type = std::ptrdiff_t;
  using reference = clang::ento::mutex_modeling::CritSectionMarker &;
  using pointer = clang::ento::mutex_modeling::CritSectionMarker *;
};
} // namespace std

// NOTE: ProgramState macros are not used here, because the visibility of these
// GDM entries must span multiple translation units (multiple checkers).
namespace clang {
namespace ento {
template <>
struct ProgramStateTrait<clang::ento::mutex_modeling::MutexEvents>
    : public ProgramStatePartialTrait<
          clang::ento::mutex_modeling::MutexEventsTy> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};
template <>
struct ProgramStateTrait<clang::ento::mutex_modeling::CritSections>
    : public ProgramStatePartialTrait<
          clang::ento::mutex_modeling::CritSectionsTy> {
  static void *GDMIndex() {
    static int Index;
    return &Index;
  }
};
} // namespace ento
} // namespace clang

#endif
