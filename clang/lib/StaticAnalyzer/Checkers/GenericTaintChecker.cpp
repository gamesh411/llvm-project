//== GenericTaintChecker.cpp ----------------------------------- -*- C++ -*--=//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This checker defines the attack surface for generic taint propagation.
//
// The taint information produced by it might be useful to other checkers. For
// example, checkers should report errors which involve tainted data more
// aggressively, even if the involved symbols are under constrained.
//
//===----------------------------------------------------------------------===//

#include "Taint.h"
#include "Yaml.h"
#include "clang/AST/Attr.h"
#include "clang/Basic/Builtins.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "llvm/Support/YAMLTraits.h"

#include <limits>
#include <memory>
#include <utility>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

/// Check for CWE-134: Uncontrolled Format String.
constexpr llvm::StringLiteral MsgUncontrolledFormatString =
    "Untrusted data is used as a format string "
    "(CWE-134: Uncontrolled Format String)";

/// Check for:
/// CERT/STR02-C. "Sanitize data passed to complex subsystems"
/// CWE-78, "Failure to Sanitize Data into an OS Command"
constexpr llvm::StringLiteral MsgSanitizeSystemArgs =
    "Untrusted data is passed to a system call "
    "(CERT/STR02-C. Sanitize data passed to complex subsystems)";

/// Check if tainted data is used as a buffer size ins strn.. functions,
/// and allocators.
constexpr llvm::StringLiteral MsgTaintedBufferSize =
    "Untrusted data is used to specify the buffer size "
    "(CERT/STR31-C. Guarantee that storage for strings has sufficient space "
    "for character data and the null terminator)";

/// Check if tainted data is used as a custom sink's parameter.
constexpr llvm::StringLiteral MsgCustomSink =
    "Untrusted data is passed to a user-defined sink";

using ArgIndexTy = int;
using SignedArgVector = llvm::SmallVector<int, 2>;

const int InvalidArgIndex{-2};
/// Denotes the return value.
const int ReturnValueIndex{-1};

/// Check if the region the expression evaluates to is the standard input,
/// and thus, is tainted.
bool isStdin(const Expr *E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  SVal Val = C.getSVal(E);

  // stdin is a pointer, so it would be a region.
  const MemRegion *MemReg = Val.getAsRegion();

  // The region should be symbolic, we do not know it's value.
  const auto *SymReg = dyn_cast_or_null<SymbolicRegion>(MemReg);
  if (!SymReg)
    return false;

  // Get it's symbol and find the declaration region it's pointing to.
  const auto *Sm = dyn_cast<SymbolRegionValue>(SymReg->getSymbol());
  if (!Sm)
    return false;
  const auto *DeclReg = dyn_cast_or_null<DeclRegion>(Sm->getRegion());
  if (!DeclReg)
    return false;

  // This region corresponds to a declaration, find out if it's a global/extern
  // variable named stdin with the proper type.
  if (const auto *D = dyn_cast_or_null<VarDecl>(DeclReg->getDecl())) {
    D = D->getCanonicalDecl();
    if (D->getName().contains("stdin") && D->isExternC()) {
      const auto *PtrTy = dyn_cast<PointerType>(D->getType().getTypePtr());
      if (PtrTy && PtrTy->getPointeeType().getCanonicalType() ==
                       C.getASTContext().getFILEType().getCanonicalType())
        return true;
    }
  }
  return false;
}

/// Given a pointer argument, return the value it points to.
Optional<SVal> getPointeeOf(CheckerContext &C, const Expr *Arg) {
  ProgramStateRef State = C.getState();
  SVal AddrVal = C.getSVal(Arg->IgnoreParens());
  if (AddrVal.isUnknownOrUndef())
    return None;

  Optional<Loc> AddrLoc = AddrVal.getAs<Loc>();
  if (!AddrLoc)
    return None;

  QualType ArgTy = Arg->getType().getCanonicalType();
  if (!ArgTy->isPointerType())
    return State->getSVal(*AddrLoc);

  QualType ValTy = ArgTy->getPointeeType();

  // Do not dereference void pointers. Treat them as byte pointers instead.
  // FIXME: we might want to consider more than just the first byte.
  if (ValTy->isVoidType())
    ValTy = C.getASTContext().CharTy;

  return State->getSVal(*AddrLoc, ValTy);
}

/// Given a pointer, return the SVal of its pointee or if it is tainted,
/// otherwise return the pointer's SVal if tainted.
Optional<SVal> getTaintedPointeeOrPointer(CheckerContext &C, const Expr *Arg) {
  assert(Arg);
  // Check for taint.
  ProgramStateRef State = C.getState();
  Optional<SVal> PointedToSVal = getPointeeOf(C, Arg);

  if (PointedToSVal && isTainted(State, *PointedToSVal))
    return PointedToSVal;

  if (isTainted(State, Arg, C.getLocationContext()))
    return {C.getSVal(Arg)};

  return {};
}

bool isTaintedOrPointsToTainted(const Expr *E, const ProgramStateRef &State,
                                CheckerContext &C) {
  if (isTainted(State, E, C.getLocationContext()) || isStdin(E, C))
    return true;

  if (!E->getType().getTypePtr()->isPointerType())
    return false;

  Optional<SVal> V = getPointeeOf(C, E);
  return (V && isTainted(State, *V));
}

/// ArgSet is used to describe arguments relevant for taint detection or
/// taint application. A discrete set of argument indexes and a variadic
/// argument list signified by a starting index are supported.
class ArgSet {
public:
  ArgSet() = default;
  ArgSet(SignedArgVector &&DiscreteArgs)
      : DiscreteArgs(DiscreteArgs), VariadicIndex(None) {}
  ArgSet(SignedArgVector &&DiscreteArgs, ArgIndexTy VariadicIndex)
      : DiscreteArgs(DiscreteArgs), VariadicIndex(VariadicIndex) {}

  bool contains(ArgIndexTy ArgIdx) const {
    if (llvm::is_contained(DiscreteArgs, ArgIdx))
      return true;

    return VariadicIndex && ArgIdx > *VariadicIndex;
  }

  bool isEmpty() const { return DiscreteArgs.empty() && !VariadicIndex; }

  SignedArgVector ArgsUpTo(ArgIndexTy LastArgIdx) const {
    SignedArgVector Args;
    for (ArgIndexTy I = ReturnValueIndex; I <= LastArgIdx; ++I) {
      if (contains(I))
        Args.push_back(I);
    }
    return Args;
  }

private:
  SignedArgVector DiscreteArgs;
  Optional<ArgIndexTy> VariadicIndex;
};

/// A struct used to specify taint propagation rules for a function.
///
/// If any of the possible taint source arguments is tainted, all of the
/// destination arguments should also be tainted. If ReturnValueIndex is added
/// to the dst list, the return value will be tainted.
class GenericTaintRule {
  /// Arguments which are taints sinks and should be checked, and a report
  /// should be emitted if taint reaches these.
  ArgSet SinkArgs;
  /// Arguments which should be sanitized on function return.
  ArgSet FilterArgs;
  /// Arguments which can participate in taint propagationa. If any of the
  /// arguments in PropSrcArgs is tainted, all arguments in  PropDstArgs should
  /// be tainted.
  ArgSet PropSrcArgs;
  ArgSet PropDstArgs;

  /// A message that explains why the rule applies.
  Optional<StringRef> Msg;

  GenericTaintRule() = default;

  GenericTaintRule(ArgSet &&Sink, ArgSet &&Filter, ArgSet &&Src, ArgSet &&Dst,
                   Optional<StringRef> Msg = None)
      : SinkArgs(std::move(Sink)), FilterArgs(std::move(Filter)),
        PropSrcArgs(std::move(Src)), PropDstArgs(std::move(Dst)), Msg(Msg) {}

public:
  /// Make a rule that reports a warning if taint reaches any of \p SinkArgs
  /// arguments.
  static GenericTaintRule Sink(ArgSet &&SinkArgs,
                               Optional<StringRef> Msg = None) {
    return {std::move(SinkArgs), {}, {}, {}, Msg};
  }

  /// Make a rule that sanitizes all FilterArgs arguments.
  static GenericTaintRule Filter(ArgSet &&FilterArgs,
                                 Optional<StringRef> Msg = None) {
    return {{}, std::move(FilterArgs), {}, {}, Msg};
  }

  /// Make a rule that unconditionally taints all Args.
  /// If Func is provided, it must also return true for taint to propagate.
  static GenericTaintRule Source(ArgSet &&SourceArgs,
                                 Optional<StringRef> Msg = None) {
    return {{}, {}, {}, std::move(SourceArgs), Msg};
  }

  /// Make a rule that taints all PropDstArgs if any of PropSrcArgs is tainted.
  static GenericTaintRule Prop(ArgSet &&SrcArgs, ArgSet &&DstArgs,
                               Optional<StringRef> Msg = None) {
    return {{}, {}, std::move(SrcArgs), std::move(DstArgs), Msg};
  }

  /// Process a function which could either be a taint source, a taint sink, a
  /// taint filter or a taint propagator.
  void process(const CallEvent &Call, CheckerContext &C) const;

  /// Handles the resolution of indexes of type ArgIndexTy to Expr*-s.
  static const Expr *GetArgExpr(ArgIndexTy ArgIdx, const CallEvent &Call) {
    return ArgIdx == ReturnValueIndex ? Call.getOriginExpr()
                                      : Call.getArgExpr(ArgIdx);
  };

  /// Functions for custom taintedness propagation.
  static bool UntrustedEnv(CheckerContext &C);
};

class GenericTaintChecker : public Checker<check::PreCall, check::PostCall> {
public:
  static void *getTag() {
    static int Tag;
    return &Tag;
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  void printState(raw_ostream &Out, ProgramStateRef State, const char *NL,
                  const char *Sep) const override;

  enum class VariadicType { None, Src, Dst };

  /// Used to parse the configuration file.
  struct TaintConfiguration {
    using NameScopeArgs = std::tuple<std::string, std::string, SignedArgVector>;

    struct Propagation {
      std::string Name;
      std::string Scope;
      SignedArgVector SrcArgs;
      SignedArgVector DstArgs;
      VariadicType VarType;
      int VarIndex;
    };

    std::vector<Propagation> Propagations;
    std::vector<NameScopeArgs> Filters;
    std::vector<NameScopeArgs> Sinks;

    TaintConfiguration() = default;
    TaintConfiguration(const TaintConfiguration &) = default;
    TaintConfiguration(TaintConfiguration &&) = default;
    TaintConfiguration &operator=(const TaintConfiguration &) = default;
    TaintConfiguration &operator=(TaintConfiguration &&) = default;
  };

  /// Validate part of the configuration, which contains a list of argument
  /// indexes.
  void validateArgVector(CheckerManager &Mgr, const std::string &Option,
                         const SignedArgVector &Args) const;

  /// Generate a report if the expression is tainted or points to tainted data.
  bool generateReportIfTainted(const Expr *E, StringRef Msg,
                               CheckerContext &C) const;

private:
  mutable std::unique_ptr<BugType> BT;
  void initBugType() const {
    if (!BT)
      BT = std::make_unique<BugType>(this, "Use of Untrusted Data",
                                     "Untrusted Data");
  }

  /// Container type used to gather built-in and user-provided taint rules. It
  /// is temporary as it is used to finally initialize TaintRules
  /// CallDescriptionMap.
  using TmpRulesType =
      std::vector<std::pair<CallDescription, GenericTaintRule>>;
  /// Parse the config.
  void parseConfiguration(TmpRulesType &Rules, CheckerManager &Mgr,
                          const std::string &Option,
                          TaintConfiguration &&Config) const;

  template <typename ConfigEntry, typename Factory>
  void parseArgListConfig(TmpRulesType &Rules, ConfigEntry &&P, Factory F,
                          CheckerManager &Mgr, const std::string &Option) const;
  template <typename ConfigEntry, typename Factory>
  void parseRuleListConfig(TmpRulesType &Rules, ConfigEntry &&P, Factory F,
                           CheckerManager &Mgr,
                           const std::string &Option) const;

  bool checkUncontrolledFormatString(const CallEvent &Call,
                                     CheckerContext &C) const;

  void taintUnsafeSocketProtocol(const CallEvent &Call,
                                 CheckerContext &C) const;


  /// Default taint rules are initilized with the help of a CheckerContext to
  /// access the names of built-in functions like memcpy.
  void initTaintRules(CheckerContext &C) const;

  /// CallDescription currently cannot restrict matches to the global namespace
  /// only, which is why multiple CallDescriptionMaps are used, as we want to
  /// disambiguate global C functions from functions inside user-defined
  /// namespaces.
  // TODO: Remove separation to simplify matching logic once CallDescriptions
  // are more expressive.
  mutable Optional<CallDescriptionMap<GenericTaintRule>> GlobalCTaintRules;
  mutable Optional<CallDescriptionMap<GenericTaintRule>> TaintRules;
};
} // end of anonymous namespace

using TaintConfig = GenericTaintChecker::TaintConfiguration;

LLVM_YAML_IS_SEQUENCE_VECTOR(TaintConfig::Propagation)
LLVM_YAML_IS_SEQUENCE_VECTOR(TaintConfig::NameScopeArgs)

namespace llvm {
namespace yaml {
template <> struct MappingTraits<TaintConfig> {
  static void mapping(IO &IO, TaintConfig &Config) {
    IO.mapOptional("Propagations", Config.Propagations);
    IO.mapOptional("Filters", Config.Filters);
    IO.mapOptional("Sinks", Config.Sinks);
  }
};

template <> struct MappingTraits<TaintConfig::Propagation> {
  static void mapping(IO &IO, TaintConfig::Propagation &Propagation) {
    IO.mapRequired("Name", Propagation.Name);
    IO.mapOptional("Scope", Propagation.Scope);
    IO.mapOptional("SrcArgs", Propagation.SrcArgs);
    IO.mapOptional("DstArgs", Propagation.DstArgs);
    IO.mapOptional("VariadicType", Propagation.VarType,
                   GenericTaintChecker::VariadicType::None);
    IO.mapOptional("VariadicIndex", Propagation.VarIndex,
                   InvalidArgIndex);
  }
};

template <> struct ScalarEnumerationTraits<GenericTaintChecker::VariadicType> {
  static void enumeration(IO &IO, GenericTaintChecker::VariadicType &Value) {
    IO.enumCase(Value, "None", GenericTaintChecker::VariadicType::None);
    IO.enumCase(Value, "Src", GenericTaintChecker::VariadicType::Src);
    IO.enumCase(Value, "Dst", GenericTaintChecker::VariadicType::Dst);
  }
};

template <> struct MappingTraits<TaintConfig::NameScopeArgs> {
  static void mapping(IO &IO, TaintConfig::NameScopeArgs &NSA) {
    IO.mapRequired("Name", std::get<0>(NSA));
    IO.mapOptional("Scope", std::get<1>(NSA));
    IO.mapRequired("Args", std::get<2>(NSA));
  }
};
} // namespace yaml
} // namespace llvm

/// A set which is used to pass information from call pre-visit instruction
/// to the call post-visit. The values are signed integers, which are either
/// ReturnValueIndex, or indexes of the pointer/reference argument, which
/// points to data, which should be tainted on return.
REGISTER_SET_WITH_PROGRAMSTATE(TaintArgsOnPostVisit, ArgIndexTy)

void GenericTaintChecker::validateArgVector(CheckerManager &Mgr,
                                            const std::string &Option,
                                            const SignedArgVector &Args) const {
  for (int Arg : Args) {
    if (Arg < -1) {
      Mgr.reportInvalidCheckerOptionValue(
          this, Option,
          "an argument number for propagation rules greater or equal to -1");
    }
  }
}

template <typename ConfigEntry, typename Factory>
void GenericTaintChecker::parseArgListConfig(TmpRulesType &Rules,
                                             ConfigEntry &&C, Factory F,
                                             CheckerManager &Mgr,
                                             const std::string &Option) const {
  // FIXME: use structured binding in C++17
  const std::string &Name = std::get<0>(C);
  const std::string &Scope = std::get<1>(C);
  SignedArgVector Args = std::move(std::get<2>(C));
  validateArgVector(Mgr, Option, Args);
  if (!Scope.empty()) {
    Rules.push_back({{Scope.c_str(), Name.c_str()}},
                    F({std::move(Args)}, {}, nullptr));
  } else {
    Rules.push_back({Name.c_str()}, F({std::move(Args), {}, nullptr}));
  }
}

template <typename ConfigEntry, typename Factory>
void GenericTaintChecker::parseRuleListConfig(TmpRulesType &Rules,
                                              ConfigEntry &&P, Factory F,
                                              CheckerManager &Mgr,
                                              const std::string &Option) const {
  validateArgVector(Mgr, Option, P.SrcArgs);
  validateArgVector(Mgr, Option, P.DstArgs);
  bool IsSrcVariadic = P.VarType == VariadicType::Src;
  bool IsDstVariadic = P.VarType == VariadicType::Dst;

  ArgSet SrcDesc = IsSrcVariadic ? ArgSet(std::move(P.SrcArgs), P.VarIndex)
                                 : ArgSet(std::move(P.SrcArgs));
  ArgSet DstDesc = IsDstVariadic ? ArgSet(std::move(P.DstArgs), P.VarIndex)
                                 : ArgSet({std::move(P.DstArgs)});

  if (!P.Scope.empty()) {
    Rules.push_back({{P.Scope.c_str(), P.Name.c_str()}},
                    F(std::move(SrcDesc), std::move(DstDesc)));
  } else {
    Rules.push_back({{P.Name.c_str()}},
                    F(std::move(SrcDesc), std::move(DstDesc)));
  }
}

void GenericTaintChecker::parseConfiguration(
    TmpRulesType &Rules, CheckerManager &Mgr, const std::string &Option,
    TaintConfiguration &&Config) const {

  const auto parseArgListConfig = [this, &Rules, &Mgr,
                                   &Option](auto &&C, auto &&F,
                                            Optional<StringRef> Msg = None) {
    // FIXME: use structured binding in C++17 for tuples
    const std::string &Name = std::get<0>(C);
    const std::string &Scope = std::get<1>(C);
    SignedArgVector Args = std::move(std::get<2>(C));
    validateArgVector(Mgr, Option, Args);

    llvm::SmallVector<const char*, 2> NameParts;
    if (!Scope.empty()) {
      // If the Scope argument ends with "::", remove that, and use the
      // result as a part in the CallDescription.
      const char* S = new char[Scope.size()];
      StringRef(S).consume_back("::");
      NameParts.push_back(S);
    }
    NameParts.push_back(Name.c_str());
    Rules.push_back({{NameParts}, F({std::move(Args)}, Msg)});
  };

  const auto parseRuleListConfig = [this, &Rules, &Mgr, &Option](auto &&P,
                                                                 auto &&F) {
    validateArgVector(Mgr, Option, P.SrcArgs);
    validateArgVector(Mgr, Option, P.DstArgs);
    bool IsSrcVariadic = P.VarType == VariadicType::Src;
    bool IsDstVariadic = P.VarType == VariadicType::Dst;

    ArgSet SrcDesc = IsSrcVariadic ? ArgSet(std::move(P.SrcArgs), P.VarIndex)
                                   : ArgSet(std::move(P.SrcArgs));
    ArgSet DstDesc = IsDstVariadic ? ArgSet(std::move(P.DstArgs), P.VarIndex)
                                   : ArgSet({std::move(P.DstArgs)});

    llvm::SmallVector<const char *, 2> NameParts;
    if (!P.Scope.empty()) {
      // If the Scope argument ends with "::", remove that, and use the
      // result as a part in the CallDescription.
      const char* Scope = P.Scope.c_str();
      StringRef(Scope).consume_back("::");
      NameParts.push_back(Scope);
    }
    NameParts.push_back(P.Name.c_str());
    Rules.push_back(
        {{NameParts}, F(std::move(SrcDesc), std::move(DstDesc), {})});
  };

  for (auto &F : Config.Filters)
    parseArgListConfig(F, GenericTaintRule::Filter);

  for (auto &S : Config.Sinks)
    parseArgListConfig(S, GenericTaintRule::Sink, MsgCustomSink);

  for (auto &P : Config.Propagations)
    parseRuleListConfig(P, GenericTaintRule::Prop);
}

void GenericTaintChecker::initTaintRules(CheckerContext &C) const {
  // Check for exact name match for functions without builtin substitutes.
  // Use qualified name, because these are C functions without namespace.

  if (TaintRules)
    return;

  const auto &BI = C.getASTContext().BuiltinInfo;

  using TR = GenericTaintRule;

  TmpRulesType GlobalCRules{
      {{"fdopen"}, TR::Source({{ReturnValueIndex}})},
      {{"fopen"}, TR::Source({{ReturnValueIndex}})},
      {{"freopen"}, TR::Source({{ReturnValueIndex}})},
      {{"getch"}, TR::Source({{ReturnValueIndex}})},
      {{"getchar"}, TR::Source({{ReturnValueIndex}})},
      {{"getchar_unlocked"}, TR::Source({{ReturnValueIndex}})},
      {{"gets"}, TR::Source({{0}, ReturnValueIndex})},
      {{"scanf"}, TR::Source({{}, 1})},
      {{"wgetch"}, TR::Source({{}, ReturnValueIndex})},
      {{"atoi"}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{"atol"}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{"atoll"}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{"fgetc"}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{"fgetln"}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{"fgets"}, TR::Prop({{2}}, {{0}, ReturnValueIndex})},
      {{"fscanf"}, TR::Prop({{0}}, {{}, 2})},
      {{"sscanf"}, TR::Prop({{0}}, {{}, 2})},
      {{"getc"}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{"getc_unlocked"}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{"getdelim"}, TR::Prop({{3}}, {{0}})},
      {{"getline"}, TR::Prop({{2}}, {{0}})},
      {{"getw"}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{"pread"}, TR::Prop({{0, 1, 2, 3}}, {{1, ReturnValueIndex}})},
      {{"read"}, TR::Prop({{0, 2}}, {{1, ReturnValueIndex}})},
      {{"strchr"}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{"strrchr"}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{"tolower"}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{"toupper"}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, BI.getName(Builtin::BImemcpy)},
       TR::Prop({{1, 2}}, {{0, ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BImemmove)}},
       TR::Prop({{1, 2}}, {{0, ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BIstrncpy)}},
       TR::Prop({{1, 2}}, {{0, ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BIstrncat)}},
       TR::Prop({{1, 2}}, {{0, ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BIstrlcpy)}},
       TR::Prop({{1, 2}}, {{0}})},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BIstrlcat)}},
       TR::Prop({{1, 2}}, {{0}})},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BIstrndup)}},
       TR::Prop({{0, 1}}, {{ReturnValueIndex}})},
      // Process all other functions which could be defined as builtins.
      {{CDF_MaybeBuiltin, {"snprintf"}},
       TR::Prop({{1}, 3}, {{0, ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, {"sprintf"}},
       TR::Prop({{1}, 2}, {{0, ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, {"strcpy"}},
       TR::Prop({{1}}, {{0, ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, {"stpcpy"}},
       TR::Prop({{1}}, {{0, ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, {"strcat"}},
       TR::Prop({{1}}, {{0, ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, {"bcopy"}}, TR::Prop({{0, 2}}, {{1}})},
      {{CDF_MaybeBuiltin, {"strdup"}}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, {"strdupa"}}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, {"wcsdup"}}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{"system"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"popen"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"execl"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"execle"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"execlp"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"execvp"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"execvP"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"execve"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"dlopen"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BImemcpy)}},
       TR::Sink({{2}}, MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BImemmove)}},
       TR::Sink({{2}}, MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BIstrncpy)}},
       TR::Sink({{2}}, MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BIstrndup)}},
       TR::Sink({{1}}, MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {"malloc"}}, TR::Sink({{0}}, MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {"calloc"}}, TR::Sink({{0}}, MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {"alloca"}}, TR::Sink({{0}}, MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {"memccpy"}}, TR::Sink({{3}}, MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {"realloc"}}, TR::Sink({{1}}, MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {"bcopy"}}, TR::Sink({{2}}, MsgTaintedBufferSize)}};

  // `getenv` returns taint only in untrusted environments.
  if (TR::UntrustedEnv(C))
    GlobalCRules.push_back({{"getenv"}, TR::Source({{ReturnValueIndex}})});

  GlobalCTaintRules.emplace(
      std::make_move_iterator(GlobalCRules.begin()),
      std::make_move_iterator(GlobalCRules.end()));

  // User-provided taint configuration.
  TmpRulesType Rules;
  CheckerManager *Mgr = C.getAnalysisManager().getCheckerManager();
  std::string Option{"Config"};
  StringRef ConfigFile =
      Mgr->getAnalyzerOptions().getCheckerStringOption(this, Option);
  llvm::Optional<TaintConfig> Config =
      getConfiguration<TaintConfig>(*Mgr, this, Option, ConfigFile);
  if (Config)
    parseConfiguration(Rules, *Mgr, Option, std::move(Config.getValue()));

  TaintRules.emplace(
      std::make_move_iterator(Rules.begin()),
      std::make_move_iterator(Rules.end()));
}

void GenericTaintChecker::checkPreCall(const CallEvent &Call,
                                       CheckerContext &C) const {

  initTaintRules(C);

  const GenericTaintRule *MaybeGlobalCMatch = GlobalCTaintRules->lookup(Call);
  const GenericTaintRule *MaybeMatch = TaintRules->lookup(Call);
  bool ConsiderGlobalCMatch = MaybeGlobalCMatch && Call.isGlobalCFunction();

  if (ConsiderGlobalCMatch) {
    MaybeGlobalCMatch->process(Call, C);
  }

  if (!ConsiderGlobalCMatch && MaybeMatch) {
    MaybeMatch->process(Call, C);
  }

  // FIXME: These edge cases are to be eliminated from here eventually.
  //
  // Additional check that is not supported by CallDescription.
  // TODO: Make CallDescription be able to match attributes such as printf-like
  // arguments.
  if (checkUncontrolledFormatString(Call, C))
    return;

  // TODO: Modeling sockets should be done in a specific checker.
  // Socket is a source, which taints the return value.
  taintUnsafeSocketProtocol(Call, C);
}

void GenericTaintChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
  // Set the marked values as tainted. The return value only accessible from
  // checkPostStmt.
  ProgramStateRef State = C.getState();

  // Depending on what was tainted at pre-visit, we determined a set of
  // arguments which should be tainted after the function returns. These are
  // stored in the state as TaintArgsOnPostVisit set.
  TaintArgsOnPostVisitTy TaintArgs = State->get<TaintArgsOnPostVisit>();
  if (TaintArgs.isEmpty())
    return;

  assert(
      Call.getNumArgs() <=
          static_cast<size_t>(std::numeric_limits<ArgIndexTy>::max()) &&
      "ArgIndexTy is not large enough to represent the number of arguments.");
  ArgIndexTy CallNumArgs = Call.getNumArgs();

  for (ArgIndexTy ArgNum : TaintArgs) {
    // Special handling for the tainted return value.
    if (ArgNum == ReturnValueIndex) {
      State = addTaint(State, Call.getReturnValue());
      continue;
    }

    // The arguments are pointer arguments. The data they are pointing at is
    // tainted after the call.
    if (CallNumArgs < (ArgNum + 1))
      return;
    const Expr *Arg = Call.getArgExpr(ArgNum);
    Optional<SVal> V = getPointeeOf(C, Arg);
    if (V)
      State = addTaint(State, *V);
  }

  // Clear up the taint info from the state.
  State = State->remove<TaintArgsOnPostVisit>();

  if (State != C.getState()) {
    C.addTransition(State);
    return;
  }
}

void GenericTaintChecker::printState(raw_ostream & Out, ProgramStateRef State,
                                     const char *NL, const char *Sep) const {
  printTaint(State, Out, NL, Sep);
}

void GenericTaintRule::process(
    const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  assert(
      Call.getNumArgs() <=
          static_cast<size_t>(std::numeric_limits<ArgIndexTy>::max()) &&
      "ArgIndexTy is not large enough to represent the number of arguments.");

  /// Iterate every call argument, and get their corresponding Expr and SVal.
  const auto ForEachCallArg = [this, &C, &Call](auto &&F) {
    for (ArgIndexTy I = ReturnValueIndex, N = Call.getNumArgs(); I < N; ++I) {
      const Expr *E = GetArgExpr(I, Call);
      assert(E);
      SVal S = C.getSVal(E);
      F(I, E, S);
    }
  };

  /// Check for taint sinks.
  ForEachCallArg([this, &C, &State](ArgIndexTy I, const Expr *E, SVal) {
    if (SinkArgs.contains(I) && isTaintedOrPointsToTainted(E, State, C))
      C.getAnalysisManager()
          .getCheckerManager()
          ->getChecker<GenericTaintChecker>()
          ->generateReportIfTainted(E, Msg ? *Msg : MsgCustomSink, C);
  });

  /// Check for taint filters.
  ForEachCallArg([this, &State](ArgIndexTy I, const Expr *E, SVal S) {
    if (FilterArgs.contains(I))
      State = removeTaint(State, S);
  });

  /// Check for taint propagation sources.
  /// A rule is relevant if PropSrcArgs is empty, or if any of its signified args
  /// are tainted in context of the current CallEvent.
  bool IsMatching = PropSrcArgs.isEmpty();
  ForEachCallArg(
      [this, &C, &IsMatching, &State](ArgIndexTy I, const Expr *E, SVal) {
        IsMatching |=
            PropSrcArgs.contains(I) && isTaintedOrPointsToTainted(E, State, C);
      });

  if (!IsMatching)
    return;

  /// Propagate taint where it is necessary.
  // TODO: Currently, we might lose precision here: we always mark a return
  // value as tainted even if it's just a pointer, pointing to tainted data.
  ForEachCallArg([this, &C, &State](ArgIndexTy I, const Expr *E, SVal S) {
    if (PropDstArgs.contains(I))
      State = State->add<TaintArgsOnPostVisit>(I);

    Optional<SVal> MaybeValueToTaint = [E, &C, S]() -> Optional<SVal> {
      if (!E)
        return {};

      const QualType ArgTy = E->getType();

      const bool IsNonConstRef =
          ArgTy->isReferenceType() && !ArgTy.isConstQualified();
      const bool IsNonConstPtr =
          ArgTy->isPointerType() && !ArgTy->getPointeeType().isConstQualified();

      if (IsNonConstRef)
        return S;
      if (IsNonConstPtr)
        return getPointeeOf(C, E);
      return {};
    }();

    if (MaybeValueToTaint.hasValue())
      State = State->add<TaintArgsOnPostVisit>(I);
  });

  if (State != C.getState())
    C.addTransition(State);
}

bool GenericTaintRule::UntrustedEnv(CheckerContext &C) {
  return !C.getAnalysisManager()
      .getAnalyzerOptions()
      .ShouldAssumeControlledEnvironment;
}

bool GenericTaintChecker::generateReportIfTainted(const Expr *E, StringRef Msg,
                                                  CheckerContext &C) const {
  assert(E);
  Optional<SVal> TaintedSVal{getTaintedPointeeOrPointer(C, E)};

  if (!TaintedSVal)
    return false;

  // Generate diagnostic.
  if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
    initBugType();
    auto report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
    report->addRange(E->getSourceRange());
    report->addVisitor(std::make_unique<TaintBugVisitor>(*TaintedSVal));
    C.emitReport(std::move(report));
    return true;
  }
  return false;
}

/// TODO: remove checking for printf format attributes and socket whitelisting
/// from GenericTaintChecker, and that means the following functions:
/// getPrintfFormatArgumentNum,
/// GenericTaintChecker::checkUncontrolledFormatString,
/// GenericTaintChecker::taintUnsafeSocketProtocol

static bool getPrintfFormatArgumentNum(const CallEvent &Call, const CheckerContext &C,
                                ArgIndexTy &ArgNum) {
  // Find if the function contains a format string argument.
  // Handles: fprintf, printf, sprintf, snprintf, vfprintf, vprintf, vsprintf,
  // vsnprintf, syslog, custom annotated functions.
  const Decl *CallDecl = Call.getDecl();
  if (!CallDecl)
    return false;
  const FunctionDecl *FDecl = CallDecl->getAsFunction();
  if (!FDecl)
    return false;

  assert(
      Call.getNumArgs() <=
          static_cast<size_t>(std::numeric_limits<ArgIndexTy>::max()) &&
      "ArgIndexTy is not large enough to represent the number of arguments.");
  ArgIndexTy CallNumArgs = Call.getNumArgs();

  for (const auto *Format : FDecl->specific_attrs<FormatAttr>()) {
    ArgNum = Format->getFormatIdx() - 1;
    if ((Format->getType()->getName() == "printf") && CallNumArgs > ArgNum)
      return true;
  }

  // Or if a function is named setproctitle (this is a heuristic).
  if (C.getCalleeName(FDecl).contains("setproctitle")) {
    ArgNum = 0;
    return true;
  }

  return false;
}

bool GenericTaintChecker::checkUncontrolledFormatString(
    const CallEvent &Call, CheckerContext &C) const {
  // Check if the function contains a format string argument.
  int ArgNum = 0;
  if (!getPrintfFormatArgumentNum(Call, C, ArgNum))
    return false;

  // If either the format string content or the pointer itself are tainted,
  // warn.
  return generateReportIfTainted(Call.getArgExpr(ArgNum),
                                 MsgUncontrolledFormatString, C);
}

void GenericTaintChecker::taintUnsafeSocketProtocol(const CallEvent &Call,
    CheckerContext &C) const {
  if (Call.getNumArgs() < 1)
    return;
  const IdentifierInfo *ID = Call.getCalleeIdentifier();
  if (!ID)
    return;
  if (!ID->getName().equals("socket"))
    return;

  SourceLocation DomLoc = Call.getArgExpr(0)->getExprLoc();
  StringRef DomName = C.getMacroNameOrSpelling(DomLoc);
  // White list the internal communication protocols.
  bool SafeProtocol = DomName.equals("AF_SYSTEM") ||
                      DomName.equals("AF_LOCAL") || DomName.equals("AF_UNIX") ||
                      DomName.equals("AF_RESERVED_36");
  if (SafeProtocol)
    return;

  const Expr *Arg = Call.getArgExpr(0);
  Optional<SVal> V = getPointeeOf(C, Arg);
  if (V)
    C.addTransition(addTaint(C.getState(), *V));
}

/// Checker registration

void ento::registerGenericTaintChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<GenericTaintChecker>();
}

bool ento::shouldRegisterGenericTaintChecker(const CheckerManager &mgr) {
  return true;
}
