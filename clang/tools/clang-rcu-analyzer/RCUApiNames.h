//===--- RCUApiNames.h - Canonical liburcu API name recognition -*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Shared by the analyzer and by the evaluation oracles, so that all of them
// recognise exactly the same set of API calls. A divergence here would show up
// as a spurious disagreement in the imprecision measurement.
//
//===----------------------------------------------------------------------===//

#ifndef CLANG_TOOLS_CLANG_RCU_ANALYZER_RCUAPINAMES_H
#define CLANG_TOOLS_CLANG_RCU_ANALYZER_RCUAPINAMES_H

#include "llvm/ADT/StringRef.h"

namespace clang {
namespace rcu {

// liburcu does not expose its API under the names that appear in the source.
// The flavour headers rewrite them to flavour-specific symbols before the AST
// exists (rcu_read_lock -> urcu_memb_read_lock, and under _LGPL_SOURCE further
// to the inline _urcu_memb_read_lock), while the pointer accessors reach the
// AST as their exported _sym helpers. Matching therefore has to happen on the
// canonical name behind those aliases; returns an empty StringRef for calls
// that are not part of the API.
inline llvm::StringRef canonicalName(llvm::StringRef Name) {
  static const char *const FlavorPrefixes[] = {
      "_urcu_memb_", "_urcu_qsbr_", "_urcu_mb_", "_urcu_bp_", "_urcu_signal_",
      "urcu_memb_",  "urcu_qsbr_",  "urcu_mb_",  "urcu_bp_",  "urcu_signal_"};
  for (const char *Prefix : FlavorPrefixes) {
    llvm::StringRef Suffix = Name;
    if (!Suffix.consume_front(Prefix))
      continue;
    if (Suffix == "read_lock")
      return "rcu_read_lock";
    if (Suffix == "read_unlock")
      return "rcu_read_unlock";
    if (Suffix == "synchronize_rcu")
      return "synchronize_rcu";
    if (Suffix == "call_rcu")
      return "call_rcu";
    if (Suffix == "dereference")
      return "rcu_dereference";
    return llvm::StringRef();
  }

  if (Name == "rcu_read_lock" || Name == "rcu_read_unlock" ||
      Name == "rcu_assign_pointer" || Name == "synchronize_rcu" ||
      Name == "call_rcu" || Name == "rcu_dereference")
    return Name;
  if (Name == "rcu_dereference_sym" || Name == "rcu_dereference_sym2")
    return "rcu_dereference";
  if (Name == "rcu_set_pointer_sym" || Name == "rcu_cmpxchg_pointer_sym" ||
      Name == "rcu_xchg_pointer_sym")
    return "rcu_assign_pointer";
  return llvm::StringRef();
}

inline bool isApiName(llvm::StringRef Name) { return !canonicalName(Name).empty(); }

} // namespace rcu
} // namespace clang

#endif
