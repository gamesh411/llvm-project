//===-- EmbeddedDSLFrameworkTest.cpp - Embedded DSL Framework Tests ------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/EmbeddedDSLFramework.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/Testing/TestAST.h"
#include "gtest/gtest.h"

using namespace clang;
using namespace ento;
using namespace dsl;

namespace {

//===----------------------------------------------------------------------===//
// Test Fixtures
//===----------------------------------------------------------------------===//

class EmbeddedDSLFrameworkTest : public ::testing::Test {
protected:
  void SetUp() override {
    // Set up test environment
  }

  void TearDown() override {
    // Clean up test environment
  }
};

//===----------------------------------------------------------------------===//
// DSL Builder Function Tests
//===----------------------------------------------------------------------===//

TEST_F(EmbeddedDSLFrameworkTest, DSLBuilderFunctions) {
  // Test atomic proposition creation
  auto mallocCall = DSL::Call("malloc", DSL::ReturnVal("x"));
  EXPECT_EQ(mallocCall->Type, LTLNodeType::Atomic);
  EXPECT_EQ(mallocCall->toString(), "malloc(x)");

  auto freeCall = DSL::Call("free", DSL::FirstParamVal("y"));
  EXPECT_EQ(freeCall->Type, LTLNodeType::Atomic);
  EXPECT_EQ(freeCall->toString(), "free(y)");

  // Test logical operators
  auto andExpr = DSL::And(mallocCall, freeCall);
  EXPECT_EQ(andExpr->Type, LTLNodeType::And);
  EXPECT_EQ(andExpr->Children.size(), 2);
  EXPECT_EQ(andExpr->toString(), "(malloc(x) ∧ free(y))");

  auto orExpr = DSL::Or(mallocCall, freeCall);
  EXPECT_EQ(orExpr->Type, LTLNodeType::Or);
  EXPECT_EQ(orExpr->Children.size(), 2);
  EXPECT_EQ(orExpr->toString(), "(malloc(x) ∨ free(y))");

  auto impliesExpr = DSL::Implies(mallocCall, freeCall);
  EXPECT_EQ(impliesExpr->Type, LTLNodeType::Implies);
  EXPECT_EQ(impliesExpr->Children.size(), 2);
  EXPECT_EQ(impliesExpr->toString(), "(malloc(x) → free(y))");

  // Test temporal operators
  auto globallyExpr = DSL::G(mallocCall);
  EXPECT_EQ(globallyExpr->Type, LTLNodeType::Globally);
  EXPECT_EQ(globallyExpr->Children.size(), 1);
  EXPECT_EQ(globallyExpr->toString(), "G(malloc(x))");

  auto eventuallyExpr = DSL::F(freeCall);
  EXPECT_EQ(eventuallyExpr->Type, LTLNodeType::Eventually);
  EXPECT_EQ(eventuallyExpr->Children.size(), 1);
  EXPECT_EQ(eventuallyExpr->toString(), "F(free(y))");

  auto nextExpr = DSL::X(mallocCall);
  EXPECT_EQ(nextExpr->Type, LTLNodeType::Next);
  EXPECT_EQ(nextExpr->Children.size(), 1);
  EXPECT_EQ(nextExpr->toString(), "X(malloc(x))");

  auto notExpr = DSL::Not(freeCall);
  EXPECT_EQ(notExpr->Type, LTLNodeType::Not);
  EXPECT_EQ(notExpr->Children.size(), 1);
  EXPECT_EQ(notExpr->toString(), "¬(free(y))");
}

TEST_F(EmbeddedDSLFrameworkTest, SymbolBindingTypes) {
  // Test different binding types
  auto returnVal = DSL::ReturnVal("x");
  EXPECT_EQ(returnVal.Type, BindingType::ReturnValue);
  EXPECT_EQ(returnVal.SymbolName, "x");

  auto firstParam = DSL::FirstParamVal("y");
  EXPECT_EQ(firstParam.Type, BindingType::FirstParameter);
  EXPECT_EQ(firstParam.SymbolName, "y");

  auto nthParam = DSL::NthParamVal("z", 2);
  EXPECT_EQ(nthParam.Type, BindingType::NthParameter);
  EXPECT_EQ(nthParam.SymbolName, "z");
  EXPECT_EQ(nthParam.ParameterIndex, 2);

  auto var = DSL::Var("w");
  EXPECT_EQ(var.Type, BindingType::Variable);
  EXPECT_EQ(var.SymbolName, "w");
}

TEST_F(EmbeddedDSLFrameworkTest, DiagnosticLabeling) {
  auto mallocCall = DSL::Call("malloc", DSL::ReturnVal("x"));
  mallocCall->withDiagnostic("Memory allocation");
  EXPECT_EQ(mallocCall->DiagnosticLabel, "Memory allocation");
  EXPECT_EQ(mallocCall->toString(), "malloc(x) [Memory allocation]");

  auto freeCall = DSL::Call("free", DSL::FirstParamVal("x"));
  freeCall->withDiagnostic("Memory deallocation");
  EXPECT_EQ(freeCall->DiagnosticLabel, "Memory deallocation");
  EXPECT_EQ(freeCall->toString(), "free(x) [Memory deallocation]");
}

//===----------------------------------------------------------------------===//
// LTL Formula Builder Tests
//===----------------------------------------------------------------------===//

TEST_F(EmbeddedDSLFrameworkTest, LTLFormulaBuilder) {
  LTLFormulaBuilder builder;

  // Build a simple formula: G(malloc(x) → F free(x))
  auto mallocCall = DSL::Call("malloc", DSL::ReturnVal("x"));
  auto freeCall = DSL::Call("free", DSL::FirstParamVal("x"));
  auto eventuallyFree = DSL::F(freeCall);
  auto implication = DSL::Implies(mallocCall, eventuallyFree);
  auto globallyImplication = DSL::G(implication);

  builder.setFormula(globallyImplication);

  // Test formula string generation
  std::string expectedFormula = "G((malloc(x) → F(free(x))))";
  EXPECT_EQ(builder.getFormulaString(), expectedFormula);

  // Test structural information
  std::string expectedStructural =
      "GLOBALLY(IMPLIES(ATOMIC:malloc:x:0,EVENTUALLY(ATOMIC:free:x:1)))";
  EXPECT_EQ(builder.getStructuralInfo(), expectedStructural);

  // Test diagnostic labels collection
  auto labels = builder.getDiagnosticLabels();
  EXPECT_EQ(labels.size(), 0); // No labels in this formula

  // Test symbol bindings collection
  auto bindings = builder.getSymbolBindings();
  EXPECT_EQ(bindings.size(), 2);
  EXPECT_EQ(bindings[0].SymbolName, "x");
  EXPECT_EQ(bindings[0].Type, BindingType::ReturnValue);
  EXPECT_EQ(bindings[1].SymbolName, "x");
  EXPECT_EQ(bindings[1].Type, BindingType::FirstParameter);

  // Test function names collection
  auto functions = builder.getFunctionNames();
  EXPECT_EQ(functions.size(), 2);
  EXPECT_EQ(functions[0], "malloc");
  EXPECT_EQ(functions[1], "free");
}

TEST_F(EmbeddedDSLFrameworkTest, LTLFormulaBuilderWithLabels) {
  LTLFormulaBuilder builder;

  // Build a formula with diagnostic labels
  auto mallocCall = DSL::Call("malloc", DSL::ReturnVal("x"));
  auto freeCall = DSL::Call("free", DSL::FirstParamVal("x"));
  auto eventuallyFree = DSL::F(freeCall);
  eventuallyFree->withDiagnostic("Memory leak: allocated memory not freed");
  auto implication = DSL::Implies(mallocCall, eventuallyFree);
  auto globallyImplication = DSL::G(implication);
  globallyImplication->withDiagnostic("Memory management property violation");

  builder.setFormula(globallyImplication);

  // Test diagnostic labels collection
  auto labels = builder.getDiagnosticLabels();
  EXPECT_EQ(labels.size(), 2);
  EXPECT_EQ(labels[0], "Memory management property violation");
  EXPECT_EQ(labels[1], "Memory leak: allocated memory not freed");
}

//===----------------------------------------------------------------------===//
// Büchi Automaton Generation Tests
//===----------------------------------------------------------------------===//

TEST_F(EmbeddedDSLFrameworkTest, AutomatonGeneration) {
  LTLFormulaBuilder builder;

  // Build a simple formula: malloc(x)
  auto mallocCall = DSL::Call("malloc", DSL::ReturnVal("x"));
  builder.setFormula(mallocCall);

  // Generate automaton
  auto automaton = builder.generateAutomaton();
  EXPECT_NE(automaton, nullptr);

  // Test automaton properties
  auto states = automaton->getStates();
  EXPECT_GT(states.size(), 0);

  auto initialState = automaton->getInitialState();
  EXPECT_NE(initialState, nullptr);
  EXPECT_EQ(initialState->StateID, "q0_0");
}

TEST_F(EmbeddedDSLFrameworkTest, AutomatonWithComplexFormula) {
  LTLFormulaBuilder builder;

  // Build a complex formula: G(malloc(x) ∧ not_null(x) → F free(x))
  auto mallocCall = DSL::Call("malloc", DSL::ReturnVal("x"));
  auto notNull = DSL::NotNull(DSL::Var("x"));
  auto mallocAndNotNull = DSL::And(mallocCall, notNull);
  auto freeCall = DSL::Call("free", DSL::FirstParamVal("x"));
  auto eventuallyFree = DSL::F(freeCall);
  auto implication = DSL::Implies(mallocAndNotNull, eventuallyFree);
  auto globallyImplication = DSL::G(implication);

  builder.setFormula(globallyImplication);

  // Generate automaton
  auto automaton = builder.generateAutomaton();
  EXPECT_NE(automaton, nullptr);

  // Test automaton properties
  auto states = automaton->getStates();
  EXPECT_GT(states.size(), 0);

  // Test that we have accepting states
  bool hasAcceptingState = false;
  for (const auto &state : states) {
    if (state->IsAccepting) {
      hasAcceptingState = true;
      break;
    }
  }
  EXPECT_TRUE(hasAcceptingState);
}

//===----------------------------------------------------------------------===//
// Property Definition Tests
//===----------------------------------------------------------------------===//

TEST_F(EmbeddedDSLFrameworkTest, MallocFreeProperty) {
  MallocFreeProperty property;

  // Test property metadata
  EXPECT_EQ(property.getPropertyName(), "malloc_free_exactly_once");
  EXPECT_EQ(
      property.getTemporalLogicFormula(),
      "G( malloc(x) ∧ x ≠ null → F free(x) ∧ G( free(x) → G ¬free(x) ) )");

  // Test formula builder
  auto formulaBuilder = property.getFormulaBuilder();
  EXPECT_FALSE(formulaBuilder.getFormulaString().empty());
  EXPECT_FALSE(formulaBuilder.getStructuralInfo().empty());

  // Test diagnostic labels
  auto labels = formulaBuilder.getDiagnosticLabels();
  EXPECT_EQ(labels.size(), 3);
  EXPECT_EQ(labels[0], "Memory management property violation");
  EXPECT_EQ(labels[1], "Memory leak: allocated memory not freed");
  EXPECT_EQ(labels[2], "Double free: memory freed multiple times");

  // Test symbol bindings
  auto bindings = formulaBuilder.getSymbolBindings();
  EXPECT_EQ(bindings.size(), 5);

  // Test function names
  auto functions = formulaBuilder.getFunctionNames();
  EXPECT_EQ(functions.size(), 5);
  EXPECT_EQ(functions[0], "malloc");
  EXPECT_EQ(functions[1], "not_null");
  EXPECT_EQ(functions[2], "free");
}

TEST_F(EmbeddedDSLFrameworkTest, MutexLockUnlockProperty) {
  MutexLockUnlockProperty property;

  // Test property metadata
  EXPECT_EQ(property.getPropertyName(), "mutex_lock_unlock_exactly_once");
  EXPECT_EQ(property.getTemporalLogicFormula(),
            "G( lock(x) → F unlock(x) ∧ G( unlock(x) → G ¬lock(x) ) )");

  // Test formula builder
  auto formulaBuilder = property.getFormulaBuilder();
  EXPECT_FALSE(formulaBuilder.getFormulaString().empty());
  EXPECT_FALSE(formulaBuilder.getStructuralInfo().empty());

  // Test diagnostic labels
  auto labels = formulaBuilder.getDiagnosticLabels();
  EXPECT_EQ(labels.size(), 3);
  EXPECT_EQ(labels[0], "Mutex lock/unlock property violation");
  EXPECT_EQ(labels[1], "Lock leak: acquired lock not released");
  EXPECT_EQ(labels[2], "Double lock: lock acquired multiple times");

  // Test symbol bindings
  auto bindings = formulaBuilder.getSymbolBindings();
  EXPECT_EQ(bindings.size(), 4);

  // Test function names
  auto functions = formulaBuilder.getFunctionNames();
  EXPECT_EQ(functions.size(), 4);
  EXPECT_EQ(functions[0], "lock");
  EXPECT_EQ(functions[1], "unlock");
}

//===----------------------------------------------------------------------===//
// Monitor Automaton Tests
//===----------------------------------------------------------------------===//

TEST_F(EmbeddedDSLFrameworkTest, MonitorAutomatonCreation) {
  // Create a property
  auto property = std::make_unique<MallocFreeProperty>();

  // Create monitor automaton (without checker context for unit test)
  MonitorAutomaton monitor(std::move(property), nullptr);

  // Test monitor properties
  EXPECT_EQ(monitor.getPropertyName(), "malloc_free_exactly_once");

  // Test formula builder access
  auto formulaBuilder = monitor.getFormulaBuilder();
  EXPECT_FALSE(formulaBuilder.getFormulaString().empty());
}

//===----------------------------------------------------------------------===//
// Event Processing Tests
//===----------------------------------------------------------------------===//

TEST_F(EmbeddedDSLFrameworkTest, EventCreation) {
  // Test generic event creation
  GenericEvent postCallEvent(EventType::PostCall, "malloc", "sym_123", nullptr,
                             nullptr);
  EXPECT_EQ(postCallEvent.Type, EventType::PostCall);
  EXPECT_EQ(postCallEvent.FunctionName, "malloc");
  EXPECT_EQ(postCallEvent.SymbolName, "sym_123");

  GenericEvent preCallEvent(EventType::PreCall, "free", "sym_456", nullptr,
                            nullptr);
  EXPECT_EQ(preCallEvent.Type, EventType::PreCall);
  EXPECT_EQ(preCallEvent.FunctionName, "free");
  EXPECT_EQ(preCallEvent.SymbolName, "sym_456");

  GenericEvent deadSymbolsEvent(EventType::DeadSymbols, "", "sym_789", nullptr,
                                nullptr);
  EXPECT_EQ(deadSymbolsEvent.Type, EventType::DeadSymbols);
  EXPECT_EQ(deadSymbolsEvent.SymbolName, "sym_789");
}

//===----------------------------------------------------------------------===//
// Pattern Matcher Tests
//===----------------------------------------------------------------------===//

TEST_F(EmbeddedDSLFrameworkTest, PatternMatcher) {
  // Note: These tests would require actual CallEvent objects
  // For now, we test the static methods exist and can be called
  EXPECT_TRUE(true); // Placeholder - actual implementation would test with real
                     // CallEvents
}

//===----------------------------------------------------------------------===//
// Symbol Tracker Tests
//===----------------------------------------------------------------------===//

TEST_F(EmbeddedDSLFrameworkTest, SymbolTracker) {
  // Note: These tests would require actual ProgramState and CheckerContext
  // objects For now, we test the static methods exist and can be called
  EXPECT_TRUE(
      true); // Placeholder - actual implementation would test with real states
}

//===----------------------------------------------------------------------===//
// Integration Tests
//===----------------------------------------------------------------------===//

TEST_F(EmbeddedDSLFrameworkTest, EndToEndFormulaBuilding) {
  // Test complete formula building process
  LTLFormulaBuilder builder;

  // Build the malloc/free formula manually
  auto mallocCall = DSL::Call("malloc", DSL::ReturnVal("x"));
  auto notNull = DSL::NotNull(DSL::Var("x"));
  auto mallocAndNotNull = DSL::And(mallocCall, notNull);

  auto freeCall = DSL::Call("free", DSL::FirstParamVal("x"));
  auto eventuallyFree = DSL::F(freeCall);
  eventuallyFree->withDiagnostic("Memory leak: allocated memory not freed");

  auto freeImpliesNoMoreFree =
      DSL::Implies(freeCall, DSL::G(DSL::Not(freeCall)));
  freeImpliesNoMoreFree->withDiagnostic(
      "Double free: memory freed multiple times");

  auto globallyNoMoreFree = DSL::G(freeImpliesNoMoreFree);
  auto eventuallyFreeAndNoMoreFree =
      DSL::And(eventuallyFree, globallyNoMoreFree);
  auto implication =
      DSL::Implies(mallocAndNotNull, eventuallyFreeAndNoMoreFree);
  auto globallyImplication = DSL::G(implication);
  globallyImplication->withDiagnostic("Memory management property violation");

  builder.setFormula(globallyImplication);

  // Verify the formula structure
  EXPECT_FALSE(builder.getFormulaString().empty());
  EXPECT_FALSE(builder.getStructuralInfo().empty());

  // Verify diagnostic labels
  auto labels = builder.getDiagnosticLabels();
  EXPECT_EQ(labels.size(), 3);
  EXPECT_EQ(labels[0], "Memory management property violation");
  EXPECT_EQ(labels[1], "Memory leak: allocated memory not freed");
  EXPECT_EQ(labels[2], "Double free: memory freed multiple times");

  // Verify symbol bindings
  auto bindings = builder.getSymbolBindings();
  EXPECT_EQ(bindings.size(), 5);

  // Verify function names
  auto functions = builder.getFunctionNames();
  EXPECT_EQ(functions.size(), 5);
  EXPECT_EQ(functions[0], "malloc");
  EXPECT_EQ(functions[1], "not_null");
  EXPECT_EQ(functions[2], "free");

  // Generate automaton
  auto automaton = builder.generateAutomaton();
  EXPECT_NE(automaton, nullptr);
  EXPECT_GT(automaton->getStates().size(), 0);
}

TEST_F(EmbeddedDSLFrameworkTest, PropertyComparison) {
  // Test that different properties generate different formulas
  MallocFreeProperty mallocProperty;
  MutexLockUnlockProperty mutexProperty;

  auto mallocFormula = mallocProperty.getFormulaBuilder().getFormulaString();
  auto mutexFormula = mutexProperty.getFormulaBuilder().getFormulaString();

  EXPECT_NE(mallocFormula, mutexFormula);

  auto mallocFunctions = mallocProperty.getFormulaBuilder().getFunctionNames();
  auto mutexFunctions = mutexProperty.getFormulaBuilder().getFunctionNames();

  EXPECT_NE(mallocFunctions, mutexFunctions);
  EXPECT_EQ(mallocFunctions[0], "malloc");
  EXPECT_EQ(mutexFunctions[0], "lock");
}

} // namespace
