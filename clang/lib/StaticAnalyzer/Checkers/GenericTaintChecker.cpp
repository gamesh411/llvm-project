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

using ArgIdxTy = int;
using ArgVecTy = llvm::SmallVector<int, 2>;

constexpr int InvalidArgIndex{-2};
/// Denotes the return value.
constexpr int ReturnValueIndex{-1};

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
  ArgSet(ArgVecTy &&DiscreteArgs)
      : DiscreteArgs(DiscreteArgs), VariadicIndex(None) {}
  ArgSet(ArgVecTy &&DiscreteArgs, ArgIdxTy VariadicIndex)
      : DiscreteArgs(DiscreteArgs), VariadicIndex(VariadicIndex) {}

  bool contains(ArgIdxTy ArgIdx) const {
    if (llvm::is_contained(DiscreteArgs, ArgIdx))
      return true;

    return VariadicIndex && ArgIdx >= *VariadicIndex;
  }

  bool isEmpty() const { return DiscreteArgs.empty() && !VariadicIndex; }

  ArgVecTy ArgsUpTo(ArgIdxTy LastArgIdx) const {
    ArgVecTy Args;
    for (ArgIdxTy I = ReturnValueIndex; I <= LastArgIdx; ++I) {
      if (contains(I))
        Args.push_back(I);
    }
    return Args;
  }

private:
  ArgVecTy DiscreteArgs;
  Optional<ArgIdxTy> VariadicIndex;
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

  /// A message that explains why the call is sensitive to taint.
  Optional<StringRef> SinkMsg;

  GenericTaintRule() = default;

  GenericTaintRule(ArgSet &&Sink, ArgSet &&Filter, ArgSet &&Src, ArgSet &&Dst,
                   Optional<StringRef> SinkMsg = None)
      : SinkArgs(std::move(Sink)), FilterArgs(std::move(Filter)),
        PropSrcArgs(std::move(Src)), PropDstArgs(std::move(Dst)),
        SinkMsg(SinkMsg) {}

public:
  /// Make a rule that reports a warning if taint reaches any of \p FilterArgs
  /// arguments.
  static GenericTaintRule Sink(ArgSet &&SinkArgs,
                               Optional<StringRef> Msg = None) {
    return {std::move(SinkArgs), {}, {}, {}, Msg};
  }

  /// Make a rule that sanitizes all FilterArgs arguments.
  static GenericTaintRule Filter(ArgSet &&FilterArgs) {
    return {{}, std::move(FilterArgs), {}, {}};
  }

  /// Make a rule that unconditionally taints all Args.
  /// If Func is provided, it must also return true for taint to propagate.
  static GenericTaintRule Source(ArgSet &&SourceArgs) {
    return {{}, {}, {}, std::move(SourceArgs)};
  }

  /// Make a rule that taints all PropDstArgs if any of PropSrcArgs is tainted.
  static GenericTaintRule Prop(ArgSet &&SrcArgs, ArgSet &&DstArgs) {
    return {{}, {}, std::move(SrcArgs), std::move(DstArgs)};
  }

  /// Make a rule that taints all PropDstArgs if any of PropSrcArgs is tainted.
  static GenericTaintRule SinkProp(ArgSet &&SinkArgs, ArgSet &&SrcArgs,
                                   ArgSet &&DstArgs,
                                   Optional<StringRef> Msg = None) {
    return {
        std::move(SinkArgs), {}, std::move(SrcArgs), std::move(DstArgs), Msg};
  }

  /// Process a function which could either be a taint source, a taint sink, a
  /// taint filter or a taint propagator.
  void process(const CallEvent &Call, CheckerContext &C) const;

  /// Handles the resolution of indexes of type ArgIdxTy to Expr*-s.
  static const Expr *GetArgExpr(ArgIdxTy ArgIdx, const CallEvent &Call) {
    return ArgIdx == ReturnValueIndex ? Call.getOriginExpr()
                                      : Call.getArgExpr(ArgIdx);
  };

  /// Functions for custom taintedness propagation.
  static bool UntrustedEnv(CheckerContext &C);
};

using RuleLookupTy = CallDescriptionMap<GenericTaintRule>;

/// Used to parse the configuration file.
struct TaintConfiguration {
  using NameScopeArgs = std::tuple<std::string, std::string, ArgVecTy>;
  enum class VariadicType { None, Src, Dst };

  struct Common {
    std::string Name;
    std::string Scope;
  };

  struct Sink : Common {
    ArgVecTy SinkArgs;
  };

  struct Filter : Common {
    ArgVecTy FilterArgs;
  };

  struct Propagation : Common {
    ArgVecTy SrcArgs;
    ArgVecTy DstArgs;
    VariadicType VarType;
    int VarIndex;
  };

  std::vector<Propagation> Propagations;
  std::vector<Filter> Filters;
  std::vector<Sink> Sinks;

  TaintConfiguration() = default;
  TaintConfiguration(const TaintConfiguration &) = default;
  TaintConfiguration(TaintConfiguration &&) = default;
  TaintConfiguration &operator=(const TaintConfiguration &) = default;
  TaintConfiguration &operator=(TaintConfiguration &&) = default;
};

struct GenericTaintRuleParser {
  GenericTaintRuleParser(CheckerManager &Mgr) : Mgr(Mgr) {}
  /// Container type used to gather call identification objects grouped into
  /// pairs with their corresponding taint rules. It is temporary as it is used
  /// to finally initialize RuleLookupTy, which is considered to be immutable.
  using RulesContTy = std::vector<std::pair<CallDescription, GenericTaintRule>>;
  RulesContTy parseConfiguration(const std::string &Option,
                                 TaintConfiguration &&Config) const;

private:
  using NamePartTy = llvm::SmallVector<SmallString<32>, 2>;
  using CallDescAPITy = llvm::SmallVector<const char *, 2>;

  /// Validate part of the configuration, which contains a list of argument
  /// indexes.
  void validateArgVector(const std::string &Option, const ArgVecTy &Args) const;

  template <typename Config>
  auto parseNameParts(const Config &C) const -> NamePartTy;

  void parseConfig(const std::string &Option, TaintConfiguration::Sink &&P,
                   RulesContTy &Rules) const;
  void parseConfig(const std::string &Option, TaintConfiguration::Filter &&P,
                   RulesContTy &Rules) const;
  void parseConfig(const std::string &Option,
                   TaintConfiguration::Propagation &&P,
                   RulesContTy &Rules) const;

  CheckerManager &Mgr;
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

  mutable Optional<RuleLookupTy> GlobalCTaintRules;
  mutable Optional<RuleLookupTy> TaintRules;
};
} // end of anonymous namespace

/// YAML serialization mapping.
LLVM_YAML_IS_SEQUENCE_VECTOR(TaintConfiguration::Sink)
LLVM_YAML_IS_SEQUENCE_VECTOR(TaintConfiguration::Filter)
LLVM_YAML_IS_SEQUENCE_VECTOR(TaintConfiguration::Propagation)

namespace llvm {
namespace yaml {
template <> struct MappingTraits<TaintConfiguration> {
  static void mapping(IO &IO, TaintConfiguration &Config) {
    IO.mapOptional("Propagations", Config.Propagations);
    IO.mapOptional("Filters", Config.Filters);
    IO.mapOptional("Sinks", Config.Sinks);
  }
};

template <> struct MappingTraits<TaintConfiguration::Sink> {
  static void mapping(IO &IO, TaintConfiguration::Sink &Sink) {
    IO.mapRequired("Name", Sink.Name);
    IO.mapOptional("Scope", Sink.Scope);
    IO.mapRequired("Args", Sink.SinkArgs);
  }
};

template <> struct MappingTraits<TaintConfiguration::Filter> {
  static void mapping(IO &IO, TaintConfiguration::Filter &Filter) {
    IO.mapRequired("Name", Filter.Name);
    IO.mapOptional("Scope", Filter.Scope);
    IO.mapRequired("Args", Filter.FilterArgs);
  }
};

template <> struct MappingTraits<TaintConfiguration::Propagation> {
  static void mapping(IO &IO, TaintConfiguration::Propagation &Propagation) {
    IO.mapRequired("Name", Propagation.Name);
    IO.mapOptional("Scope", Propagation.Scope);
    IO.mapOptional("SrcArgs", Propagation.SrcArgs);
    IO.mapOptional("DstArgs", Propagation.DstArgs);
    IO.mapOptional("VariadicType", Propagation.VarType,
                   TaintConfiguration::VariadicType::None);
    IO.mapOptional("VariadicIndex", Propagation.VarIndex, InvalidArgIndex);
  }
};

template <> struct ScalarEnumerationTraits<TaintConfiguration::VariadicType> {
  static void enumeration(IO &IO, TaintConfiguration::VariadicType &Value) {
    IO.enumCase(Value, "None", TaintConfiguration::VariadicType::None);
    IO.enumCase(Value, "Src", TaintConfiguration::VariadicType::Src);
    IO.enumCase(Value, "Dst", TaintConfiguration::VariadicType::Dst);
  }
};
} // namespace yaml
} // namespace llvm

/// A set which is used to pass information from call pre-visit instruction
/// to the call post-visit. The values are signed integers, which are either
/// ReturnValueIndex, or indexes of the pointer/reference argument, which
/// points to data, which should be tainted on return.
REGISTER_SET_WITH_PROGRAMSTATE(TaintArgsOnPostVisit, ArgIdxTy)

void GenericTaintRuleParser::validateArgVector(const std::string &Option,
                                               const ArgVecTy &Args) const {
  for (int Arg : Args) {
    if (Arg < ReturnValueIndex) {
      Mgr.reportInvalidCheckerOptionValue(
          Mgr.getChecker<GenericTaintChecker>(), Option,
          "an argument number for propagation rules greater or equal to -1");
    }
  }
}

template <typename Config>
auto GenericTaintRuleParser::parseNameParts(const Config &C) const
    -> NamePartTy {
  NamePartTy NameParts;
  if (!C.Scope.empty()) {
    // If the Scope argument contains multiple "::" parts, those are considered
    // namespace identifiers.
    llvm::SmallVector<StringRef, 2> NSParts;
    StringRef{C.Scope}.split(NSParts, "::", /*MaxSplit*/ -1,
                             /*KeepEmpty*/ false);
    NameParts.append(NSParts.begin(), NSParts.end());
  }
  NameParts.emplace_back(C.Name);
  return NameParts;
}

void GenericTaintRuleParser::parseConfig(const std::string &Option,
                                         TaintConfiguration::Sink &&S,
                                         RulesContTy &Rules) const {
  validateArgVector(Option, S.SinkArgs);

  // The ArrayRef<const char*> API of CallDescription makes it necessary to
  // first get an owning string representation, and then get the underlying
  // C-string representation.
  // FIXME: Once CallDescription supports the (possibly move) construction via
  // ArrayRef<SmallString>, ArrayRef<std::string> or from a range, this can be
  // simplified.
  NamePartTy NameParts{parseNameParts(S)};
  CallDescAPITy CallDescParts{NameParts.size()};
  llvm::transform(NameParts, CallDescParts.begin(),
                  [](auto &&P) { return P.c_str(); });
  Rules.template emplace_back(CallDescParts,
                              GenericTaintRule::Sink(std::move(S.SinkArgs)));
}

void GenericTaintRuleParser::parseConfig(const std::string &Option,
                                         TaintConfiguration::Filter &&S,
                                         RulesContTy &Rules) const {
  validateArgVector(Option, S.FilterArgs);

  // The ArrayRef<const char*> API of CallDescription makes it necessary to
  // first get an owning string representation, and then get the underlying
  // C-string representation.
  // FIXME: Once CallDescription supports the (possibly move) construction via
  // ArrayRef<SmallString>, ArrayRef<std::string> or from a range, this can be
  // simplified.
  NamePartTy NameParts{parseNameParts(S)};
  CallDescAPITy CallDescParts{NameParts.size()};
  llvm::transform(NameParts, CallDescParts.begin(),
                  [](auto &&P) { return P.c_str(); });
  Rules.template emplace_back(
      CallDescParts, GenericTaintRule::Filter(std::move(S.FilterArgs)));
}

void GenericTaintRuleParser::parseConfig(const std::string &Option,
                                         TaintConfiguration::Propagation &&P,
                                         RulesContTy &Rules) const {
  validateArgVector(Option, P.SrcArgs);
  validateArgVector(Option, P.DstArgs);
  bool IsSrcVariadic = P.VarType == TaintConfiguration::VariadicType::Src;
  bool IsDstVariadic = P.VarType == TaintConfiguration::VariadicType::Dst;

  ArgSet SrcDesc = IsSrcVariadic ? ArgSet(std::move(P.SrcArgs), P.VarIndex)
                                 : ArgSet(std::move(P.SrcArgs));
  ArgSet DstDesc = IsDstVariadic ? ArgSet(std::move(P.DstArgs), P.VarIndex)
                                 : ArgSet(std::move(P.DstArgs));

  // The ArrayRef<const char*> API of CallDescription makes it necessary to
  // first get an owning string representation, and then get the underlying
  // C-string representation.
  // FIXME: Once CallDescription supports the (possibly move) construction via
  // ArrayRef<SmallString>, ArrayRef<std::string> or from a range, this can be
  // simplified.
  NamePartTy NameParts{parseNameParts(P)};
  CallDescAPITy CallDescParts{NameParts.size()};
  llvm::transform(NameParts, CallDescParts.begin(),
                  [](auto &&P) { return P.c_str(); });
  Rules.template emplace_back(
      CallDescParts,
      GenericTaintRule::Prop(std::move(SrcDesc), std::move(DstDesc)));
}

GenericTaintRuleParser::RulesContTy
GenericTaintRuleParser::parseConfiguration(const std::string &Option,
                                           TaintConfiguration &&Config) const {

  RulesContTy Rules;

  for (auto &F : Config.Filters)
    parseConfig(Option, std::move(F), Rules);

  for (auto &S : Config.Sinks)
    parseConfig(Option, std::move(S), Rules);

  for (auto &P : Config.Propagations)
    parseConfig(Option, std::move(P), Rules);

  return Rules;
}

void GenericTaintChecker::initTaintRules(CheckerContext &C) const {
  // Check for exact name match for functions without builtin substitutes.
  // Use qualified name, because these are C functions without namespace.

  if (GlobalCTaintRules || TaintRules)
    return;

  using RulesConstructionTy =
      std::vector<std::pair<CallDescription, GenericTaintRule>>;
  using TR = GenericTaintRule;

  const auto &BI = C.getASTContext().BuiltinInfo;

  RulesConstructionTy GlobalCRules{
      // Sources
      {{"fdopen"}, TR::Source(ArgSet{{ReturnValueIndex}})},
      {{"fopen"}, TR::Source({{ReturnValueIndex}})},
      {{"freopen"}, TR::Source({{ReturnValueIndex}})},
      {{"getch"}, TR::Source({{ReturnValueIndex}})},
      {{"getchar"}, TR::Source({{ReturnValueIndex}})},
      {{"getchar_unlocked"}, TR::Source({{ReturnValueIndex}})},
      {{"gets"}, TR::Source({{0}, ReturnValueIndex})},
      {{"scanf"}, TR::Source({{}, 1})},
      {{"wgetch"}, TR::Source({{}, ReturnValueIndex})},

      // Props
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
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BIstrncat)}},
       TR::Prop({{1, 2}}, {{0, ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BIstrlcpy)}},
       TR::Prop({{1, 2}}, {{0}})},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BIstrlcat)}},
       TR::Prop({{1, 2}}, {{0}})},
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
      {{CDF_MaybeBuiltin, {"strdup"}}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, {"strdupa"}}, TR::Prop({{0}}, {{ReturnValueIndex}})},
      {{CDF_MaybeBuiltin, {"wcsdup"}}, TR::Prop({{0}}, {{ReturnValueIndex}})},

      // Sinks
      {{"system"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"popen"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"execl"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"execle"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"execlp"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"execvp"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"execvP"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"execve"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{"dlopen"}, TR::Sink({{0}}, MsgSanitizeSystemArgs)},
      {{CDF_MaybeBuiltin, {"malloc"}}, TR::Sink({{0}}, MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {"calloc"}}, TR::Sink({{0}}, MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {"alloca"}}, TR::Sink({{0}}, MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {"memccpy"}}, TR::Sink({{3}}, MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {"realloc"}}, TR::Sink({{1}}, MsgTaintedBufferSize)},
      {{{"setproctitle"}}, TR::Sink({{0}, 1}, MsgUncontrolledFormatString)},
      {{{"setproctitle_fast"}},
       TR::Sink({{0}, 1}, MsgUncontrolledFormatString)},

      // SinkProps
      {{CDF_MaybeBuiltin, BI.getName(Builtin::BImemcpy)},
       TR::SinkProp({{2}}, {{1, 2}}, {{0, ReturnValueIndex}},
                    MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BImemmove)}},
       TR::SinkProp({{2}}, {{1, 2}}, {{0, ReturnValueIndex}},
                    MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BIstrncpy)}},
       TR::SinkProp({{2}}, {{1, 2}}, {{0, ReturnValueIndex}},
                    MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {BI.getName(Builtin::BIstrndup)}},
       TR::SinkProp({{1}}, {{0, 1}}, {{ReturnValueIndex}},
                    MsgTaintedBufferSize)},
      {{CDF_MaybeBuiltin, {"bcopy"}},
       TR::SinkProp({{2}}, {{0, 2}}, {{1}}, MsgTaintedBufferSize)}};

  // `getenv` returns taint only in untrusted environments.
  if (TR::UntrustedEnv(C)) {
    // void setproctitle_init(int argc, char *argv[], char *envp[])
    GlobalCRules.push_back(
        {{{"setproctitle_init"}}, TR::Sink({{2}}, MsgCustomSink)});
    GlobalCRules.push_back({{"getenv"}, TR::Source({{ReturnValueIndex}})});
  }

  GlobalCTaintRules.emplace(std::make_move_iterator(GlobalCRules.begin()),
                            std::make_move_iterator(GlobalCRules.end()));

  // User-provided taint configuration.
  CheckerManager *Mgr = C.getAnalysisManager().getCheckerManager();
  assert(Mgr);
  GenericTaintRuleParser ConfigParser{*Mgr};
  std::string Option{"Config"};
  StringRef ConfigFile =
      Mgr->getAnalyzerOptions().getCheckerStringOption(this, Option);
  llvm::Optional<TaintConfiguration> Config =
      getConfiguration<TaintConfiguration>(*Mgr, this, Option, ConfigFile);
  if (!Config) {
    TaintRules = RuleLookupTy{};
    return;
  }

  GenericTaintRuleParser::RulesContTy Rules{
      ConfigParser.parseConfiguration(Option, std::move(Config.getValue()))};

  TaintRules.emplace(std::make_move_iterator(Rules.begin()),
                     std::make_move_iterator(Rules.end()));
}

void GenericTaintChecker::checkPreCall(const CallEvent &Call,
                                       CheckerContext &C) const {

  initTaintRules(C);

  const GenericTaintRule *MaybeGlobalCMatch = GlobalCTaintRules->lookup(Call);
  const GenericTaintRule *MaybeMatch =
      TaintRules ? TaintRules->lookup(Call) : nullptr;
  bool ConsiderGlobalCMatch = MaybeGlobalCMatch && Call.isGlobalCFunction();

  if (ConsiderGlobalCMatch)
    MaybeGlobalCMatch->process(Call, C);

  if (!ConsiderGlobalCMatch && MaybeMatch)
    MaybeMatch->process(Call, C);

  // FIXME: These edge cases are to be eliminated from here eventually.
  //
  // Additional check that is not supported by CallDescription.
  // TODO: Make CallDescription be able to match attributes such as printf-like
  // arguments.
  checkUncontrolledFormatString(Call, C);

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

  assert(Call.getNumArgs() <=
             static_cast<std::size_t>(std::numeric_limits<ArgIdxTy>::max()) &&
         "ArgIdxTy is not large enough to represent the number of arguments.");
  ArgIdxTy CallNumArgs = Call.getNumArgs();

  for (ArgIdxTy ArgNum : TaintArgs) {
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

void GenericTaintChecker::printState(raw_ostream &Out, ProgramStateRef State,
                                     const char *NL, const char *Sep) const {
  printTaint(State, Out, NL, Sep);
}

void GenericTaintRule::process(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  assert(Call.getNumArgs() <=
             static_cast<std::size_t>(std::numeric_limits<ArgIdxTy>::max()) &&
         "ArgIdxTy is not large enough to represent the number of arguments.");

  /// Iterate every call argument, and get their corresponding Expr and SVal.
  const auto ForEachCallArg = [&C, &Call](auto &&F) {
    for (ArgIdxTy I = ReturnValueIndex, N = Call.getNumArgs(); I < N; ++I) {
      const Expr *E = GetArgExpr(I, Call);
      assert(E);
      SVal S = C.getSVal(E);
      F(I, E, S);
    }
  };

  /// Check for taint sinks.
  ForEachCallArg([this, &C, &State](ArgIdxTy I, const Expr *E, SVal) {
    if (SinkArgs.contains(I) && isTaintedOrPointsToTainted(E, State, C))
      C.getAnalysisManager()
          .getCheckerManager()
          ->getChecker<GenericTaintChecker>()
          ->generateReportIfTainted(E, SinkMsg ? *SinkMsg : MsgCustomSink, C);
  });

  /// Check for taint filters.
  ForEachCallArg([this, &C, &State](ArgIdxTy I, const Expr *E, SVal S) {
    if (FilterArgs.contains(I)) {
      State = removeTaint(State, S);
      Optional<SVal> P = getPointeeOf(C, E);
      if (P)
        State = removeTaint(State, *P);
    }
  });

  /// Check for taint propagation sources.
  /// A rule is relevant if PropSrcArgs is empty, or if any of its signified
  /// args are tainted in context of the current CallEvent.
  bool IsMatching = PropSrcArgs.isEmpty();
  ForEachCallArg(
      [this, &C, &IsMatching, &State](ArgIdxTy I, const Expr *E, SVal) {
        IsMatching |=
            PropSrcArgs.contains(I) && isTaintedOrPointsToTainted(E, State, C);
      });

  if (!IsMatching)
    return;

  /// Propagate taint where it is necessary.
  // TODO: Currently, we might lose precision here: we always mark a return
  // value as tainted even if it's just a pointer, pointing to tainted data.
  ForEachCallArg([this, &C, &State](ArgIdxTy I, const Expr *E, SVal S) {
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

static bool getPrintfFormatArgumentNum(const CallEvent &Call,
                                       const CheckerContext &C,
                                       ArgIdxTy &ArgNum) {
  // Find if the function contains a format string argument.
  // Handles: fprintf, printf, sprintf, snprintf, vfprintf, vprintf, vsprintf,
  // vsnprintf, syslog, custom annotated functions.
  const Decl *CallDecl = Call.getDecl();
  if (!CallDecl)
    return false;
  const FunctionDecl *FDecl = CallDecl->getAsFunction();
  if (!FDecl)
    return false;

  assert(Call.getNumArgs() <=
             static_cast<std::size_t>(std::numeric_limits<ArgIdxTy>::max()) &&
         "ArgIdxTy is not large enough to represent the number of arguments.");
  ArgIdxTy CallNumArgs = Call.getNumArgs();

  for (const auto *Format : FDecl->specific_attrs<FormatAttr>()) {
    ArgNum = Format->getFormatIdx() - 1;
    if ((Format->getType()->getName() == "printf") && CallNumArgs > ArgNum)
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

  C.addTransition(C.getState()->add<TaintArgsOnPostVisit>(ReturnValueIndex));
}

/// Checker registration

void ento::registerGenericTaintChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<GenericTaintChecker>();
}

bool ento::shouldRegisterGenericTaintChecker(const CheckerManager &mgr) {
  return true;
}
