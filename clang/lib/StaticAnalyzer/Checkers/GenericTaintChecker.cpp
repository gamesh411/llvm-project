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
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "llvm/Support/YAMLTraits.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <unordered_map>
#include <utility>

using namespace clang;
using namespace ento;
using namespace taint;

namespace {
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

  using ArgVector = SmallVector<unsigned, 2>;
  using SignedArgVector = SmallVector<int, 2>;

  enum class VariadicType { None, Src, Dst };

  /// Used to parse the configuration file.
  struct TaintConfiguration {
    using NameScopeArgs = std::tuple<std::string, std::string, ArgVector>;

    struct Propagation {
      std::string Name;
      std::string Scope;
      ArgVector SrcArgs;
      SignedArgVector DstArgs;
      VariadicType VarType;
      unsigned VarIndex;
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

  /// Convert SignedArgVector to ArgVector.
  ArgVector convertToArgVector(CheckerManager &Mgr, const std::string &Option,
                               const SignedArgVector &Args);

  /// Parse the config.
  void parseConfiguration(CheckerManager &Mgr, const std::string &Option,
                          TaintConfiguration &&Config);

  static const unsigned InvalidArgIndex{std::numeric_limits<unsigned>::max()};
  /// Denotes the return vale.
  static const unsigned ReturnValueIndex{std::numeric_limits<unsigned>::max() -
                                         1};

private:
  mutable std::unique_ptr<BugType> BT;
  void initBugType() const {
    if (!BT)
      BT = std::make_unique<BugType>(this, "Use of Untrusted Data",
                                     "Untrusted Data");
  }

  struct FunctionData {
    FunctionData() = delete;
    FunctionData(const FunctionDecl *FDecl, StringRef Name,
                 std::string FullName)
        : FDecl(FDecl), Name(Name), FullName(std::move(FullName)) {}
    FunctionData(const FunctionData &) = default;
    FunctionData(FunctionData &&) = default;
    FunctionData &operator=(const FunctionData &) = delete;
    FunctionData &operator=(FunctionData &&) = delete;

    static Optional<FunctionData> create(const CallEvent &Call,
                                         const CheckerContext &C) {
      if (!Call.getDecl())
        return None;

      const FunctionDecl *FDecl = Call.getDecl()->getAsFunction();
      if (!FDecl || (FDecl->getKind() != Decl::Function &&
                     FDecl->getKind() != Decl::CXXMethod))
        return None;

      StringRef Name = C.getCalleeName(FDecl);
      std::string FullName = FDecl->getQualifiedNameAsString();
      if (Name.empty() || FullName.empty())
        return None;

      return FunctionData{FDecl, Name, std::move(FullName)};
    }

    bool isInScope(StringRef Scope) const {
      return StringRef(FullName).startswith(Scope);
    }

    const FunctionDecl *const FDecl;
    const StringRef Name;
    const std::string FullName;
  };

  /// Catch taint related bugs. Check if tainted data is passed to a
  /// system call etc. Returns true on matching.
  bool checkPre(const CallEvent &Call, const FunctionData &FData,
                CheckerContext &C) const;

  /// Add taint sources on a pre-visit. Returns true on matching.
  bool addSourcesPre(const CallEvent &Call, const FunctionData &FData,
                     CheckerContext &C) const;

  /// Mark filter's arguments not tainted on a pre-visit. Returns true on
  /// matching.
  bool addFiltersPre(const CallEvent &Call, const FunctionData &FData,
                     CheckerContext &C) const;

  /// Propagate taint generated at pre-visit. Returns true on matching.
  static bool propagateFromPre(const CallEvent &Call, CheckerContext &C);

  /// Check if the region the expression evaluates to is the standard input,
  /// and thus, is tainted.
  static bool isStdin(const Expr *E, CheckerContext &C);

  /// Given a pointer argument, return the value it points to.
  static Optional<SVal> getPointeeOf(CheckerContext &C, const Expr *Arg);

  /// Check for CWE-134: Uncontrolled Format String.
  static constexpr llvm::StringLiteral MsgUncontrolledFormatString =
      "Untrusted data is used as a format string "
      "(CWE-134: Uncontrolled Format String)";
  bool checkUncontrolledFormatString(const CallEvent &Call,
                                     CheckerContext &C) const;

  /// Check for:
  /// CERT/STR02-C. "Sanitize data passed to complex subsystems"
  /// CWE-78, "Failure to Sanitize Data into an OS Command"
  static constexpr llvm::StringLiteral MsgSanitizeSystemArgs =
      "Untrusted data is passed to a system call "
      "(CERT/STR02-C. Sanitize data passed to complex subsystems)";
  bool checkSystemCall(const CallEvent &Call, StringRef Name,
                       CheckerContext &C) const;

  /// Check if tainted data is used as a buffer size ins strn.. functions,
  /// and allocators.
  static constexpr llvm::StringLiteral MsgTaintedBufferSize =
      "Untrusted data is used to specify the buffer size "
      "(CERT/STR31-C. Guarantee that storage for strings has sufficient space "
      "for character data and the null terminator)";
  bool checkTaintedBufferSize(const CallEvent &Call, CheckerContext &C) const;

  /// Check if tainted data is used as a custom sink's parameter.
  static constexpr llvm::StringLiteral MsgCustomSink =
      "Untrusted data is passed to a user-defined sink";
  bool checkCustomSinks(const CallEvent &Call, const FunctionData &FData,
                        CheckerContext &C) const;

  /// Generate a report if the expression is tainted or points to tainted data.
  bool generateReportIfTainted(const Expr *E, StringRef Msg,
                               CheckerContext &C) const;

  struct TaintPropagationRule;
  template <typename T>
  using ConfigDataMap =
      std::unordered_multimap<std::string, std::pair<std::string, T>>;
  using NameRuleMap = ConfigDataMap<TaintPropagationRule>;
  using NameArgMap = ConfigDataMap<ArgVector>;

  /// Find a function with the given name and scope. Returns the first match
  /// or the end of the map.
  template <typename T>
  static auto findFunctionInConfig(const ConfigDataMap<T> &Map,
                                   const FunctionData &FData);

  /// A struct used to specify taint propagation rules for a function.
  ///
  /// If any of the possible taint source arguments is tainted, all of the
  /// destination arguments should also be tainted. Use InvalidArgIndex in the
  /// src list to specify that all of the arguments can introduce taint. Use
  /// InvalidArgIndex in the dst arguments to signify that all the non-const
  /// pointer and reference arguments might be tainted on return. If
  /// ReturnValueIndex is added to the dst list, the return value will be
  /// tainted.
  struct TaintPropagationRule {
    using PropagationFuncType = bool (*)(bool IsTainted, const CallEvent &Call,
                                         CheckerContext &C);

    /// List of arguments which can be taint sources and should be checked.
    ArgVector SrcArgs;
    /// List of arguments which should be tainted on function return.
    ArgVector DstArgs;
    /// Index for the first variadic parameter if exist.
    unsigned VariadicIndex;
    /// Show when a function has variadic parameters. If it has, it marks all
    /// of them as source or destination.
    VariadicType VarType;
    /// Special function for tainted source determination. If defined, it can
    /// override the default behavior.
    PropagationFuncType PropagationFunc;

    TaintPropagationRule()
        : VariadicIndex(InvalidArgIndex), VarType(VariadicType::None),
          PropagationFunc(nullptr) {}

    TaintPropagationRule(ArgVector &&Src, ArgVector &&Dst,
                         VariadicType Var = VariadicType::None,
                         unsigned VarIndex = InvalidArgIndex,
                         PropagationFuncType Func = nullptr)
        : SrcArgs(std::move(Src)), DstArgs(std::move(Dst)),
          VariadicIndex(VarIndex), VarType(Var), PropagationFunc(Func) {}

    /// Get the propagation rule for a given function.
    static TaintPropagationRule
    getTaintPropagationRule(const NameRuleMap &CustomPropagations,
                            const FunctionData &FData, CheckerContext &C);

    void addSrcArg(unsigned A) { SrcArgs.push_back(A); }
    void addDstArg(unsigned A) { DstArgs.push_back(A); }

    bool isNull() const {
      return SrcArgs.empty() && DstArgs.empty() &&
             VariadicType::None == VarType;
    }

    bool isDestinationArgument(unsigned ArgNum) const {
      return llvm::is_contained(DstArgs, ArgNum);
    }

    static bool isTaintedOrPointsToTainted(const Expr *E,
                                           const ProgramStateRef &State,
                                           CheckerContext &C) {
      if (isTainted(State, E, C.getLocationContext()) || isStdin(E, C))
        return true;

      if (!E->getType().getTypePtr()->isPointerType())
        return false;

      Optional<SVal> V = getPointeeOf(C, E);
      return (V && isTainted(State, *V));
    }

    /// Pre-process a function which propagates taint according to the
    /// taint rule.
    ProgramStateRef process(const CallEvent &Call, CheckerContext &C) const;

    // Functions for custom taintedness propagation.
    static bool postSocket(bool IsTainted, const CallEvent &Call,
                           CheckerContext &C);
  };

  /// Defines a map between the propagation function's name, scope
  /// and TaintPropagationRule.
  NameRuleMap CustomPropagations;

  /// Defines a map between the filter function's name, scope and filtering
  /// args.
  NameArgMap CustomFilters;

  /// Defines a map between the sink function's name, scope and sinking args.
  NameArgMap CustomSinks;
};

const unsigned GenericTaintChecker::ReturnValueIndex;
const unsigned GenericTaintChecker::InvalidArgIndex;

// FIXME: these lines can be removed in C++17
constexpr llvm::StringLiteral GenericTaintChecker::MsgUncontrolledFormatString;
constexpr llvm::StringLiteral GenericTaintChecker::MsgSanitizeSystemArgs;
constexpr llvm::StringLiteral GenericTaintChecker::MsgTaintedBufferSize;
constexpr llvm::StringLiteral GenericTaintChecker::MsgCustomSink;
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
                   GenericTaintChecker::InvalidArgIndex);
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
/// to the call post-visit. The values are unsigned integers, which are either
/// ReturnValueIndex, or indexes of the pointer/reference argument, which
/// points to data, which should be tainted on return.
REGISTER_SET_WITH_PROGRAMSTATE(TaintArgsOnPostVisit, unsigned)

GenericTaintChecker::ArgVector
GenericTaintChecker::convertToArgVector(CheckerManager &Mgr,
                                        const std::string &Option,
                                        const SignedArgVector &Args) {
  ArgVector Result;
  for (int Arg : Args) {
    if (Arg == -1)
      Result.push_back(ReturnValueIndex);
    else if (Arg < -1) {
      Result.push_back(InvalidArgIndex);
      Mgr.reportInvalidCheckerOptionValue(
          this, Option,
          "an argument number for propagation rules greater or equal to -1");
    } else
      Result.push_back(static_cast<unsigned>(Arg));
  }
  return Result;
}

void GenericTaintChecker::parseConfiguration(CheckerManager &Mgr,
                                             const std::string &Option,
                                             TaintConfiguration &&Config) {
  for (auto &P : Config.Propagations) {
    GenericTaintChecker::CustomPropagations.emplace(
        P.Name,
        std::make_pair(P.Scope, TaintPropagationRule{
                                    std::move(P.SrcArgs),
                                    convertToArgVector(Mgr, Option, P.DstArgs),
                                    P.VarType, P.VarIndex}));
  }

  for (auto &F : Config.Filters) {
    GenericTaintChecker::CustomFilters.emplace(
        std::get<0>(F),
        std::make_pair(std::move(std::get<1>(F)), std::move(std::get<2>(F))));
  }

  for (auto &S : Config.Sinks) {
    GenericTaintChecker::CustomSinks.emplace(
        std::get<0>(S),
        std::make_pair(std::move(std::get<1>(S)), std::move(std::get<2>(S))));
  }
}

template <typename T>
auto GenericTaintChecker::findFunctionInConfig(const ConfigDataMap<T> &Map,
                                               const FunctionData &FData) {
  auto Range = Map.equal_range(std::string(FData.Name));
  auto It =
      std::find_if(Range.first, Range.second, [&FData](const auto &Entry) {
        const auto &Value = Entry.second;
        StringRef Scope = Value.first;
        return Scope.empty() || FData.isInScope(Scope);
      });
  return It != Range.second ? It : Map.end();
}

GenericTaintChecker::TaintPropagationRule
GenericTaintChecker::TaintPropagationRule::getTaintPropagationRule(
    const NameRuleMap &CustomPropagations, const FunctionData &FData,
    CheckerContext &C) {
  // TODO: Currently, we might lose precision here: we always mark a return
  // value as tainted even if it's just a pointer, pointing to tainted data.

  // Check for exact name match for functions without builtin substitutes.
  // Use qualified name, because these are C functions without namespace.
  TaintPropagationRule Rule =
      llvm::StringSwitch<TaintPropagationRule>(FData.FullName)
          // Source functions
          // TODO: Add support for vfscanf & family.
          .Case("fdopen", {{}, {ReturnValueIndex}})
          .Case("fopen", {{}, {ReturnValueIndex}})
          .Case("freopen", {{}, {ReturnValueIndex}})
          .Case("getch", {{}, {ReturnValueIndex}})
          .Case("getchar", {{}, {ReturnValueIndex}})
          .Case("getchar_unlocked", {{}, {ReturnValueIndex}})
          .Case("gets", {{}, {0, ReturnValueIndex}})
          .Case("scanf", {{}, {}, VariadicType::Dst, 1})
          .Case("socket", {{},
                           {ReturnValueIndex},
                           VariadicType::None,
                           InvalidArgIndex,
                           &TaintPropagationRule::postSocket})
          .Case("wgetch", {{}, {ReturnValueIndex}})
          // Propagating functions
          .Case("atoi", {{0}, {ReturnValueIndex}})
          .Case("atol", {{0}, {ReturnValueIndex}})
          .Case("atoll", {{0}, {ReturnValueIndex}})
          .Case("fgetc", {{0}, {ReturnValueIndex}})
          .Case("fgetln", {{0}, {ReturnValueIndex}})
          .Case("fgets", {{2}, {0, ReturnValueIndex}})
          .Case("fscanf", {{0}, {}, VariadicType::Dst, 2})
          .Case("sscanf", {{0}, {}, VariadicType::Dst, 2})
          .Case("getc", {{0}, {ReturnValueIndex}})
          .Case("getc_unlocked", {{0}, {ReturnValueIndex}})
          .Case("getdelim", {{3}, {0}})
          .Case("getline", {{2}, {0}})
          .Case("getw", {{0}, {ReturnValueIndex}})
          .Case("pread", {{0, 1, 2, 3}, {1, ReturnValueIndex}})
          .Case("read", {{0, 2}, {1, ReturnValueIndex}})
          .Case("strchr", {{0}, {ReturnValueIndex}})
          .Case("strrchr", {{0}, {ReturnValueIndex}})
          .Case("tolower", {{0}, {ReturnValueIndex}})
          .Case("toupper", {{0}, {ReturnValueIndex}})
          /// Migrated from default configuration
          ///
          /// *# size_t fread(void *ptr, size_t size, size_t nmemb, FILE *
          /// stream)
          /// - Name: fread
          ///   DstArgs: [0, -1]
          .Case("fread", {{3}, {0, ReturnValueIndex}})
          /// # int getopt(int argc, char * const argv[], const char *optstring)
          /// - Name: getopt
          ///   DstArgs: [-1]
          .Case("getopt", {{}, {ReturnValueIndex}})
          /// # int getopt_long(int argc, char * const argv[], const char
          /// *optstring, const struct option *longopts, int *longindex)
          /// - Name: getopt_long
          ///   DstArgs: [-1]
          .Case("getopt_long", {{}, {ReturnValueIndex}})
          /// # int getopt_long_only(int argc, char * const argv[], const char
          /// *optstring, const struct option *longopts, int *longindex)
          /// - Name: getopt_long_only
          ///   DstArgs: [-1]
          .Case("getopt_long_only", {{}, {ReturnValueIndex}})
          /// # char *gets(char *s)
          /// - Name: gets
          ///   DstArgs: [-1]
          /// .Case("gets", {{}, {ReturnValueIndex}}) // already mentioned
          /// # int _IO_getc(_IO_FILE * __fp)
          /// - Name: _IO_getc
          ///   DstArgs: [-1]
          .Case("_IO_getc", {{}, {ReturnValueIndex}})
          /// # int getc(FILE *stream)
          /// - Name: getc
          ///   DstArgs: [-1]
          /// .Case("getc", {{}, {ReturnValueIndex}}) // already mentioned
          /// # int fgetc(FILE *stream)
          /// - Name: fgetc
          ///   DstArgs: [-1]
          /// .Case("fgetc", {{}, {ReturnValueIndex}}) // already mentioned
          /// # int getchar(void)
          /// - Name: getchar
          ///   DstArgs: [-1]
          /// .Case("getchar", {{}, {ReturnValueIndex}}) // already mentioned
          /// # char *fgets(char *s, int size, FILE *stream)
          /// - Name: fgets
          ///   DstArgs: [0, -1]
          /// .Case("fgets", {{}, {0, ReturnValueIndex}}) // already mentioned
          /// # char *getcwd(char *buf, size_t size)
          /// - Name: getcwd
          ///   DstArgs: [0, -1]
          .Case("getcwd", {{}, {0, ReturnValueIndex}})
          /// # char *getwd(char *buf)
          /// - Name: getwd
          ///   DstArgs: [0, -1]
          .Case("getwd", {{}, {0, ReturnValueIndex}})
          /// # ssize_t readlink(const char *path, char *buf, size_t bufsiz)
          /// - Name: readlink
          ///   DstArgs: [1, -1]
          .Case("readlink", {{}, {1, ReturnValueIndex}})
          /// # char *get_current_dir_name(void)
          /// - Name: get_current_dir_name
          ///   DstArgs: [-1]
          .Case("get_current_dir_name", {{}, {ReturnValueIndex}})
          /// # char *getenv(const char *name)
          /// - Name: getenv
          ///   DstArgs: [-1]
          ///
          /// depends on analyzer option ShouldAssumeControlledEnvironment
          /// and is handled otherwise
          ///
          /// # char *secure_getenv(const char *name)
          /// - Name: secure_getenv
          ///   DstArgs: [-1]
          ///
          ///   added handling just below getenv
          ///
          /// # int gethostname(char *name, size_t len)
          /// - Name: gethostname
          ///   DstArgs: [0]
          ///
          .Case("gethostname", {{}, {0}})
          /// # int getnameinfo(const struct sockaddr *sa, socklen_t salen, char
          /// *host, size_t hostlen, char *serv, size_t servlen, int flags)
          /// - Name: getnameinfo
          ///   DstArgs: [2, 4]
          .Case("getnameinfo", {{}, {2, 4}})
          /// # int getseuserbyname(const char *linuxuser, char **selinuxuser,
          /// char **level)
          /// - Name: getseuserbyname
          ///   DstArgs: [1, 2]
          .Case("getseuserbyname", {{}, {1, 2}})
          /// # hm, might need some way to get rid of the second indirection ?
          /// # int getgroups(int size, gid_t list[])
          /// - Name: getgroups
          ///   DstArgs: [1]
          .Case("getgroups", {{}, {1}})
          /// # char *getlogin(void)
          /// - Name: getlogin
          ///   DstArgs: [-1]
          .Case("getlogin", {{}, {ReturnValueIndex}})
          /// # int getlogin_r(char *buf, size_t bufsize)
          /// - Name: getlogin_r
          ///   DstArgs: [0]
          .Case("getlogin_r", {{}, {0}})
          /// # ssize_t read(int fd, void *buf, size_t count)
          /// - Name: read
          ///   DstArgs: [1, -1]
          /// already handled
          ///
          /// # ssize_t readv(int fd, const struct iovec *iov, int iovcnt)  ?
          /// iov needs an extra indirection ???
          /// - Name: readv
          ///   DstArgs: [1, -1]
          .Case("readv", {{0}, {1, ReturnValueIndex}})
          /// # ssize_t recv(int sockfd, void *buf, size_t len, int flags)
          /// - Name: recv
          ///   DstArgs: [1, -1]
          .Case("recv", {{0}, {1, ReturnValueIndex}})
          /// # ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
          /// struct sockaddr *src_addr, socklen_t *addrlen)
          /// - Name: recvfrom
          ///   DstArgs: [1, -1]
          .Case("recvfrom", {{0}, {1, ReturnValueIndex}})
          /// # int scanf(const char *format, ...)
          /// - Name: scanf
          ///   VariadicType: Dst
          ///   VariadicIndex: 1
          /// already handled
          ///
          /// # int scanf_s(const char *format, ...)
          /// - Name: scanf_s
          ///   VariadicType: Dst
          ///   VariadicIndex: 1
          .Case("scanf_s", {{0}, {}, VariadicType::Dst, 1})
          /// # int fscanf(FILE *stream, const char *format, ...)
          /// - Name: fscanf
          ///   VariadicType: Dst
          ///   VariadicIndex: 2
          /// already handled
          ///
          /// # int fscanf_s(FILE *stream, const char *format, ...)
          /// - Name: fscanf_s
          ///   VariadicType: Dst
          ///   VariadicIndex: 2
          .Case("fscanf_s", {{0}, {}, VariadicType::Dst, 2})
          /// # int vscanf(const char *format, va_list ap)
          /// - Name: vscanf
          ///   DstArgs: [1]
          .Case("vscanf", {{0}, {1}})
          /// # int vfscanf(FILE *stream, const char *format, va_list ap)
          /// - Name: vfscanf
          ///   DstArgs: [1]
          .Case("vfscanf", {{0}, {1}})
          /// # int ttyname_r(int fd, char *buf, size_t buflen)
          /// - Name: ttyname_r
          ///   DstArgs: [1, -1]
          .Case("ttyname_r", {{0}, {1, ReturnValueIndex}})
          /// # int ttyname(int fd)
          /// - Name: ttyname
          ///   DstArgs: [-1]
          .Case("ttyname_r", {{0}, {ReturnValueIndex}})
          ///  # char *dirname(char *path)
          ///  - Name: dirname
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("dirname", {{0}, {ReturnValueIndex}})
          ///  # char *basename(char *path)
          ///  - Name: basename
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("basename", {{0}, {ReturnValueIndex}})
          ///  # int fnmatch(const char *pattern, const char *string, int flags)
          ///  - Name: fnmatch
          ///    SrcArgs: [1]
          ///    DstArgs: [-1]
          .Case("fnmatch", {{0}, {ReturnValueIndex}})
          ///  # int mbtowc(wchar_t *pwc, const char *s, size_t n)
          ///  - Name: mbtowc
          ///    SrcArgs: [1]
          ///    DstArgs: [0, -1]
          .Case("mbtowc", {{1}, {0, ReturnValueIndex}})
          ///  # void *memchr(const void *s, int c, size_t n)
          ///  - Name: memchr
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("memchr", {{0}, {ReturnValueIndex}})
          ///  # void *memrchr(const void *s, int c, size_t n)
          ///  - Name: memrchr
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("memrchr", {{0}, {ReturnValueIndex}})
          ///  # void *rawmemchr(const void *s, int c)
          ///  - Name: rawmemchr
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("rawmemchr", {{0}, {ReturnValueIndex}})
          ///  # int memcmp(const void *s1, const void *s2, size_t n)
          ///  - Name: memcmp
          ///    SrcArgs: [0, 1]
          ///    DstArgs: [-1]
          .Case("memcmp", {{0, 1}, {ReturnValueIndex}})
          ///  # void *memcpy(void *dest, const void *src, size_t n)
          ///  - Name: memcpy
          ///    SrcArgs: [1]
          ///    DstArgs: [0, -1]
          .Case("memcpy", {{1}, {0, ReturnValueIndex}})
          ///  # void *memmove(void *dest, const void *src, size_t n)
          ///  - Name: memmove
          ///    SrcArgs: [1]
          ///    DstArgs: [0, -1]
          .Case("memmove", {{1}, {0, ReturnValueIndex}})
          ///  # void *memmem(const void *haystack, size_t haystacklen, const
          ///  void *needle, size_t needlelen)
          ///  - Name: memmem
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("memmem", {{0}, {ReturnValueIndex}})
          ///  # char *strstr(const char *haystack, const char *needle)     ???
          ///  - Name: strstr
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("strstr", {{0}, {ReturnValueIndex}})
          ///  # char *strcasestr(const char *haystack, const char *needle) ???
          ///  - Name: strcasestr
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("strcasestr", {{0}, {ReturnValueIndex}})
          ///  # char *strchr(const char *s, int c)    ???
          ///  - Name: strchr
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          /// already handled
          ///
          ///  # char *strrchr(const char *s, int c)
          ///  - Name: strrchr
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          /// already handled
          ///
          ///  # char *strchrnul(const char *s, int c)
          ///  - Name: strchrnul
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("strchrnul", {{0}, {ReturnValueIndex}})
          ///  # char *index(const char *s, int c)
          ///  - Name: index
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("index", {{0}, {ReturnValueIndex}})
          ///  # char *rindex(const char *s, int c)
          ///  - Name: rindex
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("rindex", {{0}, {ReturnValueIndex}})
          ///  # do we need this two? why is this not by default? ???
          ///  # void qsort(void *base, size_t nmemb, size_t size, int
          ///  (*compar)(const void *, const void *))
          ///  - Name: qsort
          ///    SrcArgs: [0]
          ///    DstArgs: [0]
          .Case("qsort", {{0}, {0}})
          ///  # void qsort_r(void *base, size_t nmemb, size_t size, int
          ///  (*compar)(const void *, const void *, void *), void *arg)
          ///  - Name: qsort_r
          ///    SrcArgs: [0]
          ///    DstArgs: [0]
          .Case("qsort_r", {{0}, {0}})
          ///  # int strcmp(const char *s1, const char *s2)
          ///  - Name: strcmp
          ///    SrcArgs: [0, 1]
          ///    DstArgs: [-1]
          .Case("strcmp", {{0, 1}, {ReturnValueIndex}})
          ///  # int strcasecmp(const char *s1, const char *s2)
          ///  - Name: strcasecmp
          ///    SrcArgs: [0, 1]
          ///    DstArgs: [-1]
          .Case("strcasecmp", {{0, 1}, {ReturnValueIndex}})
          ///  # int strncmp(const char *s1, const char *s2, size_t n)
          ///  - Name: strncmp
          ///    SrcArgs: [0, 1, 2]
          ///    DstArgs: [-1]
          .Case("strncmp", {{0, 1, 2}, {ReturnValueIndex}})
          ///  # int strncasecmp(const char *s1, const char *s2, size_t n)
          ///  - Name: strncasecmp
          ///    SrcArgs: [0, 1, 2]
          ///    DstArgs: [-1]
          .Case("strncasecmp", {{0, 1, 2}, {ReturnValueIndex}})
          ///  # size_t strspn(const char *s, const char *accept)  ???
          ///  - Name: strspn
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("strspn", {{0}, {ReturnValueIndex}})
          ///  # size_t strcspn(const char *s, const char *reject) ???
          ///  - Name: strcspn
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("strcspn", {{0}, {ReturnValueIndex}})
          ///  # char *strpbrk(const char *s, const char *accept)
          ///  - Name: strpbrk
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("strpbrk", {{0}, {ReturnValueIndex}})
          ///  # char *strdup(const char *s)
          ///  - Name: strdup
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          /// handled below
          ///
          ///  # char *strndup(const char *s, size_t n)
          ///  - Name: strndup
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("strndup", {{0}, {ReturnValueIndex}})
          ///  # char *strdupa(const char *s)
          ///  - Name: strdupa
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          /// handled below
          ///
          ///  # char *strndupa(const char *s, size_t n)
          ///  - Name: strndupa
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("strndupa", {{0}, {ReturnValueIndex}})
          ///  # size_t strlen(const char *s)
          ///  - Name: strlen
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("strlen", {{0}, {ReturnValueIndex}})
          ///  # size_t strnlen(const char *s, size_t maxlen)
          ///  - Name: strnlen
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("strnlen", {{0}, {ReturnValueIndex}})
          ///  # hm, might need some way to get rid of the second indirection ?
          ///  # this has quite complex semantics
          ///  # char *strsep(char **stringp, const char *delim)
          ///  - Name: strsep
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("strsep", {{0}, {ReturnValueIndex}})
          ///  # long int strtol(const char *nptr, char **endptr, int base)
          ///  - Name: strtol
          ///    SrcArgs: [0]
          ///    DstArgs: [1, -1]
          .Case("strtol", {{0}, {1, ReturnValueIndex}})
          ///  # long long int strtoll(const char *nptr, char **endptr, int
          ///  base)
          ///  - Name: strtoll
          ///    SrcArgs: [0]
          ///    DstArgs: [1, -1]
          .Case("strtoll", {{0}, {1, ReturnValueIndex}})
          ///  # unsigned long int strtoul(const char *nptr, char **endptr, int
          ///  base)
          ///  - Name: strtoul
          ///    SrcArgs: [0]
          ///    DstArgs: [1, -1]
          .Case("strtoul", {{0}, {1, ReturnValueIndex}})
          ///  # unsigned long long int strtoull(const char *nptr, char
          ///  **endptr, int base)
          ///  - Name: strtoull
          ///    SrcArgs: [0]
          ///    DstArgs: [1, -1]
          .Case("strtoull", {{0}, {1, ReturnValueIndex}})
          ///  # int wctomb(char *s, wchar_t wc)
          ///  - Name: wctomb
          ///    SrcArgs: [1]
          ///    DstArgs: [0]
          .Case("wctomb", {{1}, {0}})
          ///  # int wcwidth(wchar_t c)
          ///  - Name: wcwidth
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("wcwidth", {{0}, {ReturnValueIndex}})
          ///  # int isalnum(int c)
          ///  - Name: isalnum
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("isalnum", {{0}, {ReturnValueIndex}})
          ///  # int isalpha(int c)
          ///  - Name: isalpha
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("isalpha", {{0}, {ReturnValueIndex}})
          ///  # int isascii(int c)
          ///  - Name: isascii
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("isascii", {{0}, {ReturnValueIndex}})
          ///  # int isblank(int c)
          ///  - Name: isblank
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("isblank", {{0}, {ReturnValueIndex}})
          ///  # int iscntrl(int c)
          ///  - Name: iscntrl
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("iscntrl", {{0}, {ReturnValueIndex}})
          ///  # int isdigit(int c)
          ///  - Name: isdigit
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("isdigit", {{0}, {ReturnValueIndex}})
          ///  # int isgraph(int c)
          ///  - Name: isgraph
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("isgraph", {{0}, {ReturnValueIndex}})
          ///  # int islower(int c)
          ///  - Name: islower
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("islower", {{0}, {ReturnValueIndex}})
          ///  # int isprint(int c)
          ///  - Name: isprint
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("isprint", {{0}, {ReturnValueIndex}})
          ///  # int ispunct(int c)
          ///  - Name: ispunct
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("ispunct", {{0}, {ReturnValueIndex}})
          ///  # int isspace(int c)
          ///  - Name: isspace
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("isspace", {{0}, {ReturnValueIndex}})
          ///  # int isupper(int c)
          ///  - Name: isupper
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("isupper", {{0}, {ReturnValueIndex}})
          ///  # int isxdigit(int c)
          ///  - Name: isxdigit
          ///    SrcArgs: [0]
          ///    DstArgs: [-1]
          .Case("isxdigit", {{0}, {ReturnValueIndex}})
          ///  # ZLIB (decompression, aka. inflate)
          ///  # int inflate(z_streamp strm, int flush)
          ///  - Name: inflate
          ///    DstArgs: [0]
          // If there is no taint generator for z_streamp this being an
          // unconditional source is best.
          .Case("inflate", {{0}, {ReturnValueIndex}})
          ///  # OpenSSL (if the `in` tainted, `out` should be tainted as well)
          ///  # void AES_encrypt(const unsigned char *in, unsigned char *out,
          ///  const AES_KEY *key)
          ///  - Name: AES_encrypt
          ///    SrcArgs: [0]
          ///    DstArgs: [1]
          .Case("AES_encrypt", {{0}, {1}})
          ///  # void AES_decrypt(const unsigned char *in, unsigned char *out,
          ///  const AES_KEY *key)
          ///  - Name: AES_decrypt
          ///    SrcArgs: [0]
          ///    DstArgs: [1]
          .Case("AES_decrypt", {{0}, {1}})
          ///  # embedthis goahead webserver:
          ///  # cchar* websGetVar(Webs *wp, cchar *name, cchar *defaultValue)
          ///  - Name: websGetVar
          ///    DstArgs: [-1]
          .Case("websGetVar", {{}, {ReturnValueIndex}})

          .Default({});

  if (!Rule.isNull())
    return Rule;

  // `getenv` returns taint only in untrusted environments.
  if (FData.FullName == "getenv") {
    if (C.getAnalysisManager()
            .getAnalyzerOptions()
            .ShouldAssumeControlledEnvironment)
      return {};
    return {{}, {ReturnValueIndex}};
  }

  // `secure_getenv` returns taint only in untrusted environments.
  // It is debatable whether this can be consiedered "safe enough"
  // to not taint the value returned at all.
  if (FData.FullName == "secure_getenv") {
    if (C.getAnalysisManager()
            .getAnalyzerOptions()
            .ShouldAssumeControlledEnvironment)
      return {};
    return {{}, {ReturnValueIndex}};
  }

  assert(FData.FDecl);

  // Check if it's one of the memory setting/copying functions.
  // This check is specialized but faster then calling isCLibraryFunction.
  const FunctionDecl *FDecl = FData.FDecl;
  unsigned BId = 0;
  if ((BId = FDecl->getMemoryFunctionKind())) {
    switch (BId) {
    case Builtin::BImemcpy:
    case Builtin::BImemmove:
    case Builtin::BIstrncpy:
    case Builtin::BIstrncat:
      return {{1, 2}, {0, ReturnValueIndex}};
    case Builtin::BIstrlcpy:
    case Builtin::BIstrlcat:
      return {{1, 2}, {0}};
    case Builtin::BIstrndup:
      return {{0, 1}, {ReturnValueIndex}};

    default:
      break;
    }
  }

  // Process all other functions which could be defined as builtins.
  if (Rule.isNull()) {
    const auto OneOf = [FDecl](const auto &... Name) {
      // FIXME: use fold expression in C++17
      using unused = int[];
      bool ret = false;
      static_cast<void>(unused{
          0, (ret |= CheckerContext::isCLibraryFunction(FDecl, Name), 0)...});
      return ret;
    };
    if (OneOf("snprintf"))
      return {{1}, {0, ReturnValueIndex}, VariadicType::Src, 3};
    if (OneOf("sprintf"))
      return {{1}, {0, ReturnValueIndex}, VariadicType::Src, 2};
    if (OneOf("strcpy", "stpcpy", "strcat"))
      return {{1}, {0, ReturnValueIndex}};
    if (OneOf("bcopy"))
      return {{0, 2}, {1}};
    if (OneOf("strdup", "strdupa", "wcsdup"))
      return {{0}, {ReturnValueIndex}};
  }

  // Skipping the following functions, since they might be used for cleansing or
  // smart memory copy:
  // - memccpy - copying until hitting a special character.

  auto It = findFunctionInConfig(CustomPropagations, FData);
  if (It != CustomPropagations.end())
    return It->second.second;
  return {};
}

void GenericTaintChecker::checkPreCall(const CallEvent &Call,
                                       CheckerContext &C) const {
  Optional<FunctionData> FData = FunctionData::create(Call, C);
  if (!FData)
    return;

  // Check for taintedness related errors first: system call, uncontrolled
  // format string, tainted buffer size.
  if (checkPre(Call, *FData, C))
    return;

  // Marks the function's arguments and/or return value tainted if it present in
  // the list.
  if (addSourcesPre(Call, *FData, C))
    return;

  addFiltersPre(Call, *FData, C);
}

void GenericTaintChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
  // Set the marked values as tainted. The return value only accessible from
  // checkPostStmt.
  propagateFromPre(Call, C);
}

void GenericTaintChecker::printState(raw_ostream &Out, ProgramStateRef State,
                                     const char *NL, const char *Sep) const {
  printTaint(State, Out, NL, Sep);
}

bool GenericTaintChecker::addSourcesPre(const CallEvent &Call,
                                        const FunctionData &FData,
                                        CheckerContext &C) const {
  // First, try generating a propagation rule for this function.
  TaintPropagationRule Rule = TaintPropagationRule::getTaintPropagationRule(
      this->CustomPropagations, FData, C);
  if (!Rule.isNull()) {
    ProgramStateRef State = Rule.process(Call, C);
    if (State) {
      C.addTransition(State);
      return true;
    }
  }
  return false;
}

bool GenericTaintChecker::addFiltersPre(const CallEvent &Call,
                                        const FunctionData &FData,
                                        CheckerContext &C) const {
  auto It = findFunctionInConfig(CustomFilters, FData);
  if (It == CustomFilters.end())
    return false;

  ProgramStateRef State = C.getState();
  const auto &Value = It->second;
  const ArgVector &Args = Value.second;
  for (unsigned ArgNum : Args) {
    if (ArgNum >= Call.getNumArgs())
      continue;

    const Expr *Arg = Call.getArgExpr(ArgNum);
    Optional<SVal> V = getPointeeOf(C, Arg);
    if (V)
      State = removeTaint(State, *V);
  }

  if (State != C.getState()) {
    C.addTransition(State);
    return true;
  }
  return false;
}

bool GenericTaintChecker::propagateFromPre(const CallEvent &Call,
                                           CheckerContext &C) {
  ProgramStateRef State = C.getState();

  // Depending on what was tainted at pre-visit, we determined a set of
  // arguments which should be tainted after the function returns. These are
  // stored in the state as TaintArgsOnPostVisit set.
  TaintArgsOnPostVisitTy TaintArgs = State->get<TaintArgsOnPostVisit>();
  if (TaintArgs.isEmpty())
    return false;

  for (unsigned ArgNum : TaintArgs) {
    // Special handling for the tainted return value.
    if (ArgNum == ReturnValueIndex) {
      State = addTaint(State, Call.getReturnValue());
      continue;
    }

    // The arguments are pointer arguments. The data they are pointing at is
    // tainted after the call.
    if (Call.getNumArgs() < (ArgNum + 1))
      return false;
    const Expr *Arg = Call.getArgExpr(ArgNum);
    Optional<SVal> V = getPointeeOf(C, Arg);
    if (V)
      State = addTaint(State, *V);
  }

  // Clear up the taint info from the state.
  State = State->remove<TaintArgsOnPostVisit>();

  if (State != C.getState()) {
    C.addTransition(State);
    return true;
  }
  return false;
}

bool GenericTaintChecker::checkPre(const CallEvent &Call,
                                   const FunctionData &FData,
                                   CheckerContext &C) const {
  if (checkUncontrolledFormatString(Call, C))
    return true;

  if (checkSystemCall(Call, FData.Name, C))
    return true;

  if (checkTaintedBufferSize(Call, C))
    return true;

  return checkCustomSinks(Call, FData, C);
}

Optional<SVal> GenericTaintChecker::getPointeeOf(CheckerContext &C,
                                                 const Expr *Arg) {
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

ProgramStateRef
GenericTaintChecker::TaintPropagationRule::process(const CallEvent &Call,
                                                   CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Check for taint in arguments.
  bool IsTainted = true;
  for (unsigned ArgNum : SrcArgs) {
    if (ArgNum >= Call.getNumArgs())
      continue;

    if ((IsTainted =
             isTaintedOrPointsToTainted(Call.getArgExpr(ArgNum), State, C)))
      break;
  }

  // Check for taint in variadic arguments.
  if (!IsTainted && VariadicType::Src == VarType) {
    // Check if any of the arguments is tainted
    for (unsigned i = VariadicIndex; i < Call.getNumArgs(); ++i) {
      if ((IsTainted =
               isTaintedOrPointsToTainted(Call.getArgExpr(i), State, C)))
        break;
    }
  }

  if (PropagationFunc)
    IsTainted = PropagationFunc(IsTainted, Call, C);

  if (!IsTainted)
    return State;

  // Mark the arguments which should be tainted after the function returns.
  for (unsigned ArgNum : DstArgs) {
    // Should mark the return value?
    if (ArgNum == ReturnValueIndex) {
      State = State->add<TaintArgsOnPostVisit>(ReturnValueIndex);
      continue;
    }

    if (ArgNum >= Call.getNumArgs())
      continue;

    // Mark the given argument.
    State = State->add<TaintArgsOnPostVisit>(ArgNum);
  }

  // Mark all variadic arguments tainted if present.
  if (VariadicType::Dst == VarType) {
    // For all pointer and references that were passed in:
    //   If they are not pointing to const data, mark data as tainted.
    //   TODO: So far we are just going one level down; ideally we'd need to
    //         recurse here.
    for (unsigned i = VariadicIndex; i < Call.getNumArgs(); ++i) {
      const Expr *Arg = Call.getArgExpr(i);
      // Process pointer argument.
      const Type *ArgTy = Arg->getType().getTypePtr();
      QualType PType = ArgTy->getPointeeType();
      if ((!PType.isNull() && !PType.isConstQualified()) ||
          (ArgTy->isReferenceType() && !Arg->getType().isConstQualified())) {
        State = State->add<TaintArgsOnPostVisit>(i);
      }
    }
  }

  return State;
}

// If argument 0(protocol domain) is network, the return value should get taint.
bool GenericTaintChecker::TaintPropagationRule::postSocket(
    bool /*IsTainted*/, const CallEvent &Call, CheckerContext &C) {
  SourceLocation DomLoc = Call.getArgExpr(0)->getExprLoc();
  StringRef DomName = C.getMacroNameOrSpelling(DomLoc);
  // White list the internal communication protocols.
  if (DomName.equals("AF_SYSTEM") || DomName.equals("AF_LOCAL") ||
      DomName.equals("AF_UNIX") || DomName.equals("AF_RESERVED_36"))
    return false;
  return true;
}

bool GenericTaintChecker::isStdin(const Expr *E, CheckerContext &C) {
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

static bool getPrintfFormatArgumentNum(const CallEvent &Call,
                                       const CheckerContext &C,
                                       unsigned &ArgNum) {
  // Find if the function contains a format string argument.
  // Handles: fprintf, printf, sprintf, snprintf, vfprintf, vprintf, vsprintf,
  // vsnprintf, syslog, custom annotated functions.
  const FunctionDecl *FDecl = Call.getDecl()->getAsFunction();
  if (!FDecl)
    return false;
  for (const auto *Format : FDecl->specific_attrs<FormatAttr>()) {
    ArgNum = Format->getFormatIdx() - 1;
    if ((Format->getType()->getName() == "printf") &&
        Call.getNumArgs() > ArgNum)
      return true;
  }

  // Or if a function is named setproctitle (this is a heuristic).
  if (C.getCalleeName(FDecl).contains("setproctitle")) {
    ArgNum = 0;
    return true;
  }

  return false;
}

bool GenericTaintChecker::generateReportIfTainted(const Expr *E, StringRef Msg,
                                                  CheckerContext &C) const {
  assert(E);

  // Check for taint.
  ProgramStateRef State = C.getState();
  Optional<SVal> PointedToSVal = getPointeeOf(C, E);
  SVal TaintedSVal;
  if (PointedToSVal && isTainted(State, *PointedToSVal))
    TaintedSVal = *PointedToSVal;
  else if (isTainted(State, E, C.getLocationContext()))
    TaintedSVal = C.getSVal(E);
  else
    return false;

  // Generate diagnostic.
  if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
    initBugType();
    auto report = std::make_unique<PathSensitiveBugReport>(*BT, Msg, N);
    report->addRange(E->getSourceRange());
    report->addVisitor(std::make_unique<TaintBugVisitor>(TaintedSVal));
    C.emitReport(std::move(report));
    return true;
  }
  return false;
}

bool GenericTaintChecker::checkUncontrolledFormatString(
    const CallEvent &Call, CheckerContext &C) const {
  // Check if the function contains a format string argument.
  unsigned ArgNum = 0;
  if (!getPrintfFormatArgumentNum(Call, C, ArgNum))
    return false;

  // If either the format string content or the pointer itself are tainted,
  // warn.
  return generateReportIfTainted(Call.getArgExpr(ArgNum),
                                 MsgUncontrolledFormatString, C);
}

bool GenericTaintChecker::checkSystemCall(const CallEvent &Call, StringRef Name,
                                          CheckerContext &C) const {
  // TODO: It might make sense to run this check on demand. In some cases,
  // we should check if the environment has been cleansed here. We also might
  // need to know if the user was reset before these calls(seteuid).
  unsigned SensitiveArgs = llvm::StringSwitch<ArgVector>(Name)
                        .Case("system", {0})
                        .Case("popen", {0})
                        /// # int execl(const char *path, const char *arg0, ... , (char *)0)
                        /// - Name: execl
                        ///   Args: [0, 1]
                        .Case("execl", {0, 1})
                        /// # int execle(const char *path, const char *arg0, ... ,(char *)0, char *const envp[])
                        /// - Name: execle
                        ///   Args: [0, 1]
                        .Case("execle", {0, 1})
                        /// # int execlp(const char *file, const char *arg0, ... , (char *)0)
                        /// - Name: execlp
                        ///   Args: [0, 1]
                        .Case("execlp", {0, 1})
                        /// # int execv(const char *path, char *const argv[])
                        /// - Name: execv
                        ///   Args: [0, 1]
                        .Case("execv", {0, 1})
                        /// # int execvp(const char *file, char *const argv[])
                        /// - Name: execvp
                        ///   Args: [0, 1]
                        .Case("execvp", {0, 1})
                        .Case("execvP", {0})
                        /// # int execve(const char *path, char *const argv[], char *const envp[])
                        /// - Name: execve
                        ///   Args: [0, 1, 2]
                        .Case("execve", {0, 1, 2})
                        .Case("dlopen", {0})
                        .Default({});

  bool isReported = false;
  for (const auto &Arg : SensitiveArgs) {
    /// FIXME: Should we report EVERY arg or just the first?
    isReported |=
        (Call.getNumArgs() < (SensitiveArgs + 1)) &&
        generateReportIfTainted(Call.getArgExpr(Arg), MsgSanitizeSystemArgs, C);
  }
  return isReported;
}

// TODO: Should this check be a part of the CString checker?
// If yes, should taint be a global setting?
// Only the first sensitive argument (that is acutally tainted) is relevant, as
// we may not want to emit warnings multiple times for the same call.
bool GenericTaintChecker::checkTaintedBufferSize(const CallEvent &Call,
                                                 CheckerContext &C) const {
  const auto *FDecl = Call.getDecl()->getAsFunction();
  // If the function has a buffer size argument, set ArgNum.
  unsigned ArgNum = InvalidArgIndex;
  unsigned BId = 0;
  if ((BId = FDecl->getMemoryFunctionKind())) {
    switch (BId) {
    case Builtin::BImemcpy:
    case Builtin::BImemmove:
    case Builtin::BIstrncpy:
      ArgNum = 2;
      break;
    case Builtin::BIstrndup:
      ArgNum = 1;
      break;
    default:
      break;
    }
  }

  if (ArgNum == InvalidArgIndex) {
    using CCtx = CheckerContext;
        /// # void *malloc(size_t size)
        /// - Name: malloc
        ///   Args: [0]
    if (CCtx::isCLibraryFunction(FDecl, "malloc") ||
        /// # void *calloc(size_t nmemb, size_t size)
        /// - Name: calloc
        ///   Args: [0, 1]
        CCtx::isCLibraryFunction(FDecl, "calloc") ||
        CCtx::isCLibraryFunction(FDecl, "alloca"))
      ArgNum = 0;
    else if (CCtx::isCLibraryFunction(FDecl, "memccpy"))
      ArgNum = 3;
        /// # void *realloc(void *ptr, size_t size)
        /// - Name: realloc
        ///   Args: [1]
    else if (CCtx::isCLibraryFunction(FDecl, "realloc"))
      ArgNum = 1;
    else if (CCtx::isCLibraryFunction(FDecl, "bcopy"))
      ArgNum = 2;
  }


  /// # int shutdown(int sockfd, int how)
  /// - Name: shutdown
  ///   Args: [1]

  /// # void *memset(void *s, int c, size_t n)  ???
  /// - Name: memset
  ///   Args: [1, 2]

  /// # https://www.cvedetails.com/cve/CVE-2006-2451
  /// # int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
  /// - Name: prctl
  ///   Args: [0]

  /// # int system(const char *command)
  /// - Name: system
  ///   Args: [0]

  /// # int sprintf(char *str, const char *format, ...)
  /// - Name: sprintf
  ///   Args: [1,2,3,4,5,6,7,8]

  /// # int snprintf(char *str, size_t size, const char *format, ...)
  /// - Name: snprintf
  ///   Args: [2,3,4,5,6,7,8]

  /// # int vsprintf(char *str, const char *format, va_list ap)
  /// - Name: vsprintf
  ///   Args: [1, 2]

  /// # int vsnprintf(char *str, size_t size, const char *format, va_list ap)
  /// - Name: vsnprintf
  ///   Args: [2, 3]

  /// # int sscanf(const char *str, const char *format, ...)
  /// - Name: sscanf
  ///   Args: [1,2,3,4,5,6,7,8]

  /// # int sscanf_s(const char *restrict str, const char *restrict format, ...)
  /// - Name: sscanf_s
  ///   Args: [1,2,3,4,5,6,7,8]

  /// # int vsscanf(const char *str, const char *format, va_list ap)
  /// - Name: vsscanf
  ///   Args: [0, 1, 2]

  return ArgNum != InvalidArgIndex && Call.getNumArgs() > ArgNum &&
         generateReportIfTainted(Call.getArgExpr(ArgNum), MsgTaintedBufferSize,
                                 C);
}

bool GenericTaintChecker::checkCustomSinks(const CallEvent &Call,
                                           const FunctionData &FData,
                                           CheckerContext &C) const {
  auto It = findFunctionInConfig(CustomSinks, FData);
  if (It == CustomSinks.end())
    return false;

  const auto &Value = It->second;
  const GenericTaintChecker::ArgVector &Args = Value.second;
  for (unsigned ArgNum : Args) {
    if (ArgNum >= Call.getNumArgs())
      continue;

    if (generateReportIfTainted(Call.getArgExpr(ArgNum), MsgCustomSink, C))
      return true;
  }

  return false;
}

void ento::registerGenericTaintChecker(CheckerManager &Mgr) {
  auto *Checker = Mgr.registerChecker<GenericTaintChecker>();
  std::string Option{"Config"};
  StringRef ConfigFile =
      Mgr.getAnalyzerOptions().getCheckerStringOption(Checker, Option);
  llvm::Optional<TaintConfig> Config =
      getConfiguration<TaintConfig>(Mgr, Checker, Option, ConfigFile);
  if (Config)
    Checker->parseConfiguration(Mgr, Option, std::move(Config.getValue()));
}

bool ento::shouldRegisterGenericTaintChecker(const CheckerManager &mgr) {
  return true;
}
