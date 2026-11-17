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
// A loss of sign in a symbolic value is reported only if the negative value is
// backed by evidence on the path: the code itself compares the value against a
// non-positive constant, tests it for equality with a negative constant, or
// compares the operands of a difference. A value that is negative solely
// because the analyzer took the exit of a loop, split a "<= 0" range with
// "!= 0", or modelled a call is not reported, as such a path only exists
// because the analyzer does not know the invariants of the program. A value
// that is a known constant is reported as before.
//
// Many compilers and tools have similar checks that are based on semantic
// analysis. Those checks are sound but have poor precision. ConversionChecker
// is an alternative to those checks.
//
//===----------------------------------------------------------------------===//
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/ParentMap.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporterVisitors.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/SmallPtrSet.h"

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
                 const char Msg[], bool IsLossOfSign) const;
};
}

namespace {
/// Returns true and sets \p CondE and \p TookTrue if the analyzer assumed the
/// outcome of a condition at \p N. Relational and equality comparisons are
/// assumed eagerly at the comparison itself, other conditions on the block
/// edge that leaves the terminator.
bool getBranchDecision(const ExplodedNode *N, const Expr *&CondE,
                       bool &TookTrue) {
  const auto &Tags = ExprEngine::getEagerlyAssumeBifurcationTags();
  ProgramPoint PP = N->getLocation();
  if (auto PS = PP.getAs<PostStmt>()) {
    const ProgramPointTag *Tag = PS->getTag();
    if (Tag != Tags.first && Tag != Tags.second)
      return false;
    CondE = dyn_cast<Expr>(PS->getStmt());
    TookTrue = Tag == Tags.first;
    return CondE;
  }
  if (auto BE = PP.getAs<BlockEdge>()) {
    const CFGBlock *Src = BE->getSrc();
    CondE = dyn_cast_or_null<Expr>(Src->getTerminatorCondition());
    TookTrue = CondE && *Src->succ_begin() == BE->getDst();
    return CondE;
  }
  return false;
}

/// Is \p E, possibly nested in logical operators, the condition of a loop?
bool isLoopCondition(const Expr *E, const LocationContext *LCtx) {
  const ParentMap &PM = LCtx->getParentMap();
  const Stmt *Child = E;
  const Stmt *Parent = PM.getParent(Child);
  while (Parent && isa<Expr>(Parent)) {
    Child = Parent;
    Parent = PM.getParent(Parent);
  }
  if (const auto *F = dyn_cast_or_null<ForStmt>(Parent))
    return F->getCond() == Child;
  if (const auto *W = dyn_cast_or_null<WhileStmt>(Parent))
    return W->getCond() == Child;
  if (const auto *D = dyn_cast_or_null<DoStmt>(Parent))
    return D->getCond() == Child;
  return false;
}

bool sharesSymbol(SymbolRef Sym, const llvm::SmallPtrSetImpl<SymbolRef> &Set) {
  if (!Sym)
    return false;
  for (SymbolRef S : Sym->symbols())
    if (Set.contains(S))
      return true;
  return false;
}

/// For "X op C" (or "C op X" if \p ConstOnLHS), computes the upper bound that
/// the taken branch implies for X. Returns false if it implies none.
bool impliedUpperBound(BinaryOperatorKind Op, bool ConstOnLHS, bool TookTrue,
                       const llvm::APSInt &C, llvm::APSInt &UpperBound) {
  if (C.isUnsigned())
    return false; // A mixed-sign comparison does not bound the signed value.
  if (ConstOnLHS)
    Op = BinaryOperator::reverseComparisonOp(Op);
  if (!TookTrue)
    Op = BinaryOperator::negateComparisonOp(Op);
  if (Op != BO_LT && Op != BO_LE)
    return false;
  UpperBound = C;
  if (Op == BO_LT) {
    if (C.isMinSignedValue())
      return false; // "X < INT_MIN" is infeasible, there is no bound.
    --UpperBound;
  }
  return true;
}

/// Does \p State entail V < 0? The same notion as CheckerContext::isNegative,
/// for a state that is not the current one.
bool isKnownNegative(ProgramStateRef State, SVal V) {
  if (!isa<NonLoc>(V))
    return false;
  SValBuilder &SVB = State->getStateManager().getSValBuilder();
  SVal Zero = SVB.makeIntVal(0, /*isUnsigned=*/false);
  SVal Cmp = SVB.evalBinOp(State, BO_LT, V, Zero, SVB.getConditionType());
  auto Def = Cmp.getAs<DefinedSVal>();
  if (!Def)
    return false;
  auto [StTrue, StFalse] = State->assume(*Def);
  return StTrue && !StFalse;
}

/// Invalidates a loss-of-sign report unless the path contains evidence that
/// the negative value is something the program can really produce.
///
/// The analyzer knows a value to be negative only because of the constraints
/// it collected along the path. Some of them come from explicit tests of the
/// program (\c if (n < 0), \c n == -1, \c if (off > len) for len - off). Others
/// are by-products of the analysis: the exit of a loop whose counter starts
/// at zero (\c n <= 0), the complement of a positivity guard combined with a
/// zero test (\c n <= 0 && n != 0) or the analyzer's own modelling. Counts,
/// sizes and lengths that are non-negative by an invariant the analyzer cannot
/// see produce the latter kind in large numbers.
class ExplicitSignTestVisitor final : public BugReporterVisitor {
  SVal V;
  llvm::SmallPtrSet<SymbolRef, 4> Symbols;
  bool HasEvidence = false;

public:
  explicit ExplicitSignTestVisitor(SVal V) : V(V) {
    if (SymbolRef Sym = V.getAsSymbol())
      for (SymbolRef S : Sym->symbols())
        Symbols.insert(S);
  }

  void Profile(llvm::FoldingSetNodeID &ID) const override {
    static int Tag = 0;
    ID.AddPointer(&Tag);
    V.Profile(ID);
  }

  PathDiagnosticPieceRef VisitNode(const ExplodedNode *N,
                                   BugReporterContext &BRC,
                                   PathSensitiveBugReport &BR) override {
    if (!HasEvidence && !Symbols.empty())
      HasEvidence = isExplicitSignTest(N);
    return nullptr;
  }

  void finalizeVisitor(BugReporterContext &BRC, const ExplodedNode *EndPathNode,
                       PathSensitiveBugReport &BR) override {
    // A known constant has no path constraints to blame, keep it.
    if (!Symbols.empty() && !HasEvidence) {
      static int InvalidationTag;
      BR.markInvalid(&InvalidationTag, nullptr);
    }
  }

private:
  bool becameNegativeAt(const ExplodedNode *N) const {
    const ExplodedNode *Pred = N->getFirstPred();
    return Pred && isKnownNegative(N->getState(), V) &&
           !isKnownNegative(Pred->getState(), V);
  }

  bool isExplicitSignTest(const ExplodedNode *N) const {
    const Expr *CondE = nullptr;
    bool TookTrue = false;
    if (!getBranchDecision(N, CondE, TookTrue))
      return false;
    const LocationContext *LCtx = N->getLocationContext();
    if (isLoopCondition(CondE, LCtx))
      return false;
    const auto *BO = dyn_cast<BinaryOperator>(CondE->IgnoreParenImpCasts());
    if (!BO || !(BO->isRelationalOp() || BO->isEqualityOp()))
      return false;

    ProgramStateRef State = N->getState();
    SVal LHS = State->getSVal(BO->getLHS(), LCtx);
    SVal RHS = State->getSVal(BO->getRHS(), LCtx);
    bool LHSRelated = sharesSymbol(LHS.getAsSymbol(), Symbols);
    bool RHSRelated = sharesSymbol(RHS.getAsSymbol(), Symbols);
    if (!LHSRelated && !RHSRelated)
      return false;

    std::optional<llvm::APSInt> LHSConst, RHSConst;
    if (auto CI = LHS.getAs<nonloc::ConcreteInt>())
      LHSConst = CI->getValue();
    if (auto CI = RHS.getAs<nonloc::ConcreteInt>())
      RHSConst = CI->getValue();
    BinaryOperatorKind Op = BO->getOpcode();

    if (LHSConst && RHSConst)
      return false;

    if (!LHSConst && !RHSConst) {
      // A relation between two symbolic values tests the sign of V only if V
      // is a difference-like expression of exactly these operands. For a bare
      // symbol it is a clamp or a size relation, e.g. FFMIN(a, b).
      return !isa<SymbolData>(V.getAsSymbol()) && LHSRelated && RHSRelated &&
             Op != BO_EQ && Op != BO_NE;
    }

    const llvm::APSInt &C = LHSConst ? *LHSConst : *RHSConst;
    if (Op == BO_EQ || Op == BO_NE) {
      bool EqualityHolds = (Op == BO_EQ) == TookTrue;
      return EqualityHolds && C.isSigned() && C.isNegative();
    }
    // The sign of an expression such as -len is determined by a test of any
    // direction on its operand: len > 0 makes -len negative. Accept such a
    // test if it is the point where the expression became known negative.
    if (!isa<SymbolData>(V.getAsSymbol()) && becameNegativeAt(N))
      return true;
    llvm::APSInt UpperBound;
    if (!impliedUpperBound(Op, /*ConstOnLHS=*/LHSConst.has_value(), TookTrue, C,
                           UpperBound))
      return false;
    return !UpperBound.isStrictlyPositive();
  }
};
} // namespace

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
                /*IsLossOfSign=*/true);
    if (LossOfPrecision)
      reportBug(N, Cast, C, "Loss of precision in implicit conversion",
                /*IsLossOfSign=*/false);
  }
}

void ConversionChecker::reportBug(ExplodedNode *N, const Expr *E,
                                  CheckerContext &C, const char Msg[],
                                  bool IsLossOfSign) const {
  // Generate a report for this bug.
  auto R = std::make_unique<PathSensitiveBugReport>(BT, Msg, N);
  bugreporter::trackExpressionValue(N, E, *R);
  if (IsLossOfSign)
    R->addVisitor(std::make_unique<ExplicitSignTestVisitor>(
        C.getSVal(cast<ImplicitCastExpr>(E)->getSubExpr())));
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
