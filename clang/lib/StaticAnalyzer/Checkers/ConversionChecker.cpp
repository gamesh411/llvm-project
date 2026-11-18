//=== ConversionChecker.cpp -------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Check that there is no loss of sign/precision in assignments, comparisons
// and multiplications.
//
// ConversionChecker uses path sensitive analysis to determine possible values
// of expressions. A warning is reported when:
// * a negative value is implicitly converted to an unsigned value in an
//   assignment, comparison or multiplication.
// * assignment / initialization when the source value is greater than the max
//   value of the target integer type
// * assignment / initialization when the source integer is above the range
//   where the target floating point type can represent all integers
//
// A loss of sign is not reported if the value is known to be non-positive only
// because the analyzer assumed a loop condition to be false. Leaving a loop
// that counts up from zero bounds the count by zero, and counts, sizes and
// lengths are rarely allowed to be negative.
//
// Many compilers and tools have similar checks that are based on semantic
// analysis. Those checks are sound but have poor precision. ConversionChecker
// is an alternative to those checks.
//
//===----------------------------------------------------------------------===//
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporterVisitors.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "llvm/ADT/APFloat.h"

#include <climits>

using namespace clang;
using namespace ento;

namespace {
class ConversionChecker : public Checker<check::PreStmt<ImplicitCastExpr>> {
public:
  void checkPreStmt(const ImplicitCastExpr *Cast, CheckerContext &C) const;

private:
  const BugType BT{this, "Conversion"};

  bool isLossOfPrecision(const ImplicitCastExpr *Cast, QualType DestType,
                         CheckerContext &C) const;

  bool isLossOfSign(const ImplicitCastExpr *Cast, CheckerContext &C) const;

  void reportBug(ExplodedNode *N, const Expr *E, CheckerContext &C,
                 const char Msg[],
                 std::unique_ptr<BugReporterVisitor> Visitor = nullptr) const;
};

/// Invalidates a loss-of-sign report if the upper bound that makes the value
/// non-positive comes from assuming a loop condition to be false.
///
/// The bound is looked for instead of the point where the value became
/// negative, because the latter is often an innocent test: after
/// \code
///   for (i = 0; i < n; i++) {}
///   if (n != 0) use(n);
/// \endcode
/// it is the exit of the loop that keeps n from being positive, the second test
/// only excludes zero.
class LoopBoundVisitor final : public BugReporterVisitor {
  SVal V;
  bool FoundBound = false;

public:
  explicit LoopBoundVisitor(SVal V) : V(V) {}

  void Profile(llvm::FoldingSetNodeID &ID) const override {
    static int Tag = 0;
    ID.AddPointer(&Tag);
    ID.Add(V);
  }

  PathDiagnosticPieceRef VisitNode(const ExplodedNode *N,
                                   BugReporterContext &BRC,
                                   PathSensitiveBugReport &BR) override;
};
} // namespace

/// Does \p State entail V <= 0?
static bool isKnownNonPositive(ProgramStateRef State, SVal V) {
  if (!isa<NonLoc>(V))
    return false;
  SValBuilder &SVB = State->getStateManager().getSValBuilder();
  SVal NonPositive =
      SVB.evalBinOp(State, BO_LE, V, SVB.makeIntVal(0, /*isUnsigned=*/false),
                    SVB.getConditionType());
  if (NonPositive.isUnknownOrUndef())
    return false;
  auto [StTrue, StFalse] = State->assume(NonPositive.castAs<DefinedSVal>());
  return StTrue && !StFalse;
}

/// Returns the condition whose outcome the analyzer assumed at \p N and sets
/// \p Outcome. A comparison is assumed eagerly, right after it is evaluated,
/// other conditions on the edge that leaves the branching block.
static const Stmt *getAssumedCondition(const ExplodedNode *N, bool &Outcome) {
  ProgramPoint PP = N->getLocation();
  if (auto Edge = PP.getAs<BlockEdge>()) {
    const CFGBlock *Src = Edge->getSrc();
    Outcome = *Src->succ_begin() == Edge->getDst();
    return Src->getTerminatorCondition();
  }
  if (auto PS = PP.getAs<PostStmt>()) {
    const auto &[TrueTag, FalseTag] =
        ExprEngine::getEagerlyAssumeBifurcationTags();
    Outcome = PS->getTag() == TrueTag;
    if (Outcome || PS->getTag() == FalseTag)
      return PS->getStmt();
  }
  return nullptr;
}

/// Is \p S the condition of a loop, or an operand of it?
static bool isPartOfLoopCondition(const Stmt *S, const ParentMap &PM) {
  const Stmt *Parent = PM.getParent(S);
  while (Parent && isa<Expr>(Parent)) {
    S = Parent;
    Parent = PM.getParent(S);
  }
  if (const auto *For = dyn_cast_or_null<ForStmt>(Parent))
    return For->getCond() == S;
  if (const auto *While = dyn_cast_or_null<WhileStmt>(Parent))
    return While->getCond() == S;
  if (const auto *Do = dyn_cast_or_null<DoStmt>(Parent))
    return Do->getCond() == S;
  if (const auto *RangeFor = dyn_cast_or_null<CXXForRangeStmt>(Parent))
    return RangeFor->getCond() == S;
  return false;
}

PathDiagnosticPieceRef LoopBoundVisitor::VisitNode(const ExplodedNode *N,
                                                   BugReporterContext &BRC,
                                                   PathSensitiveBugReport &BR) {
  // The bound holds at the end of the path and constraints only accumulate,
  // so the first node whose predecessor does not have it is its origin.
  const ExplodedNode *Pred = N->getFirstPred();
  if (FoundBound || !Pred || isKnownNonPositive(Pred->getState(), V))
    return nullptr;
  FoundBound = true;

  bool Outcome = false;
  const Stmt *Cond = getAssumedCondition(N, Outcome);
  if (Cond && !Outcome &&
      isPartOfLoopCondition(Cond, N->getLocationContext()->getParentMap()))
    BR.markInvalid("Suppress loop bound", N->getLocationContext());
  return nullptr;
}

/// Returns the value of \p E as it was before the analyzer replaced a symbol
/// that is constrained to a single value by that value. Only the constraints
/// of the symbol tell where such a value comes from.
static SVal getValueBeforeFolding(const Expr *E, CheckerContext &C) {
  SVal V = C.getSVal(E);
  const auto *Load = dyn_cast<ImplicitCastExpr>(E->IgnoreParens());
  if (!V.isConstant() || !Load || Load->getCastKind() != CK_LValueToRValue)
    return V;
  auto L = C.getSVal(Load->getSubExpr()).getAs<Loc>();
  if (!L)
    return V;
  SVal Stored = C.getState()->getRawSVal(*L, Load->getType());
  return Stored.getAsSymbol() ? Stored : V;
}

void ConversionChecker::checkPreStmt(const ImplicitCastExpr *Cast,
                                     CheckerContext &C) const {
  // Don't warn for implicit conversions to bool
  if (Cast->getType()->isBooleanType())
    return;

  // Don't warn for loss of sign/precision in macros.
  if (Cast->getExprLoc().isMacroID())
    return;

  // Get Parent.
  const ParentMap &PM = C.getLocationContext()->getParentMap();
  const Stmt *Parent = PM.getParent(Cast);
  if (!Parent)
    return;
  // Dont warn if this is part of an explicit cast
  if (isa<ExplicitCastExpr>(Parent))
    return;

  bool LossOfSign = false;
  bool LossOfPrecision = false;

  // Loss of sign/precision in binary operation.
  if (const auto *B = dyn_cast<BinaryOperator>(Parent)) {
    BinaryOperator::Opcode Opc = B->getOpcode();
    if (Opc == BO_Assign) {
      if (!Cast->IgnoreParenImpCasts()->isEvaluatable(C.getASTContext())) {
        LossOfSign = isLossOfSign(Cast, C);
        LossOfPrecision = isLossOfPrecision(Cast, Cast->getType(), C);
      }
    } else if (Opc == BO_AddAssign || Opc == BO_SubAssign) {
      // No loss of sign.
      LossOfPrecision = isLossOfPrecision(Cast, B->getLHS()->getType(), C);
    } else if (Opc == BO_MulAssign) {
      LossOfSign = isLossOfSign(Cast, C);
      LossOfPrecision = isLossOfPrecision(Cast, B->getLHS()->getType(), C);
    } else if (Opc == BO_DivAssign || Opc == BO_RemAssign) {
      LossOfSign = isLossOfSign(Cast, C);
      // No loss of precision.
    } else if (Opc == BO_AndAssign) {
      LossOfSign = isLossOfSign(Cast, C);
      // No loss of precision.
    } else if (Opc == BO_OrAssign || Opc == BO_XorAssign) {
      LossOfSign = isLossOfSign(Cast, C);
      LossOfPrecision = isLossOfPrecision(Cast, B->getLHS()->getType(), C);
    } else if (B->isRelationalOp() || B->isMultiplicativeOp()) {
      LossOfSign = isLossOfSign(Cast, C);
    }
  } else if (isa<DeclStmt, ReturnStmt>(Parent)) {
    if (!Cast->IgnoreParenImpCasts()->isEvaluatable(C.getASTContext())) {
      LossOfSign = isLossOfSign(Cast, C);
      LossOfPrecision = isLossOfPrecision(Cast, Cast->getType(), C);
    }
  } else {
    LossOfSign = isLossOfSign(Cast, C);
    LossOfPrecision = isLossOfPrecision(Cast, Cast->getType(), C);
  }

  if (LossOfSign || LossOfPrecision) {
    // Generate an error node.
    ExplodedNode *N = C.generateNonFatalErrorNode(C.getState());
    if (!N)
      return;
    if (LossOfSign)
      reportBug(N, Cast, C, "Loss of sign in implicit conversion",
                std::make_unique<LoopBoundVisitor>(
                    getValueBeforeFolding(Cast->getSubExpr(), C)));
    if (LossOfPrecision)
      reportBug(N, Cast, C, "Loss of precision in implicit conversion");
  }
}

void ConversionChecker::reportBug(
    ExplodedNode *N, const Expr *E, CheckerContext &C, const char Msg[],
    std::unique_ptr<BugReporterVisitor> Visitor) const {
  // Generate a report for this bug.
  auto R = std::make_unique<PathSensitiveBugReport>(BT, Msg, N);
  bugreporter::trackExpressionValue(N, E, *R);
  if (Visitor)
    R->addVisitor(std::move(Visitor));
  C.emitReport(std::move(R));
}

bool ConversionChecker::isLossOfPrecision(const ImplicitCastExpr *Cast,
                                          QualType DestType,
                                          CheckerContext &C) const {
  // Don't warn about explicit loss of precision.
  if (Cast->isEvaluatable(C.getASTContext()))
    return false;

  QualType SubType = Cast->IgnoreParenImpCasts()->getType();

  if (!DestType->isRealType() || !SubType->isIntegerType())
    return false;

  const bool isFloat = DestType->isFloatingType();

  const auto &AC = C.getASTContext();

  // We will find the largest RepresentsUntilExp value such that the DestType
  // can exactly represent all nonnegative integers below 2^RepresentsUntilExp.
  unsigned RepresentsUntilExp;

  if (isFloat) {
    const llvm::fltSemantics &Sema = AC.getFloatTypeSemantics(DestType);
    RepresentsUntilExp = llvm::APFloat::semanticsPrecision(Sema);
  } else {
    RepresentsUntilExp = AC.getIntWidth(DestType);
    if (RepresentsUntilExp == 1) {
      // This is just casting a number to bool, probably not a bug.
      return false;
    }
    if (DestType->isSignedIntegerType())
      RepresentsUntilExp--;
  }

  if (RepresentsUntilExp >= sizeof(unsigned long long) * CHAR_BIT) {
    // Avoid overflow in our later calculations.
    return false;
  }

  unsigned CorrectedSrcWidth = AC.getIntWidth(SubType);
  if (SubType->isSignedIntegerType())
    CorrectedSrcWidth--;

  if (RepresentsUntilExp >= CorrectedSrcWidth) {
    // Simple case: the destination can store all values of the source type.
    return false;
  }

  unsigned long long MaxVal = 1ULL << RepresentsUntilExp;
  if (isFloat) {
    // If this is a floating point type, it can also represent MaxVal exactly.
    MaxVal++;
  }
  return C.isGreaterOrEqual(Cast->getSubExpr(), MaxVal);
  // TODO: maybe also check negative values with too large magnitude.
}

bool ConversionChecker::isLossOfSign(const ImplicitCastExpr *Cast,
                                     CheckerContext &C) const {
  QualType CastType = Cast->getType();
  QualType SubType = Cast->IgnoreParenImpCasts()->getType();

  if (!CastType->isUnsignedIntegerType() || !SubType->isSignedIntegerType())
    return false;

  return C.isNegative(Cast->getSubExpr());
}

void ento::registerConversionChecker(CheckerManager &mgr) {
  mgr.registerChecker<ConversionChecker>();
}

bool ento::shouldRegisterConversionChecker(const CheckerManager &mgr) {
  return true;
}
