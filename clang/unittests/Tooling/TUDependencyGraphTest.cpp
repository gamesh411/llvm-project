//===--- TUDependencyGraphTest.cpp - Tests for TUDependencyGraph ----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "TUDependencyGraph.h"

#include "gtest/gtest.h"

using namespace clang;
using namespace clang::exception_scan;

TEST(TUDependencyGraphTest, AddDependency) {
  TUDependencyGraph Graph;

  // Add a dependency
  Graph.addDependency("A", "B");

  // Check that the dependency exists
  EXPECT_TRUE(Graph.hasDependency("A", "B"));
  EXPECT_FALSE(Graph.hasDependency("B", "A"));
  EXPECT_FALSE(Graph.hasDependency("A", "C"));

  // Add another dependency
  Graph.addDependency("B", "C");

  // Check that both dependencies exist
  EXPECT_TRUE(Graph.hasDependency("A", "B"));
  EXPECT_TRUE(Graph.hasDependency("B", "C"));
  EXPECT_FALSE(Graph.hasDependency("A", "C"));
}

TEST(TUDependencyGraphTest, GetDependencies) {
  TUDependencyGraph Graph;

  // Add dependencies
  Graph.addDependency("A", "B");
  Graph.addDependency("A", "C");
  Graph.addDependency("B", "C");

  // Get dependencies of A
  auto Dependencies = Graph.getDependendees("A");
  EXPECT_EQ(Dependencies.size(), 2u);
  EXPECT_TRUE(std::find(Dependencies.begin(), Dependencies.end(), "B") !=
              Dependencies.end());
  EXPECT_TRUE(std::find(Dependencies.begin(), Dependencies.end(), "C") !=
              Dependencies.end());

  // Get dependencies of B
  Dependencies = Graph.getDependendees("B");
  EXPECT_EQ(Dependencies.size(), 1u);
  EXPECT_TRUE(std::find(Dependencies.begin(), Dependencies.end(), "C") !=
              Dependencies.end());

  // Get dependencies of C
  Dependencies = Graph.getDependendees("C");
  EXPECT_EQ(Dependencies.size(), 0u);
}

TEST(TUDependencyGraphTest, GetDependents) {
  TUDependencyGraph Graph;

  // Add dependencies
  Graph.addDependency("A", "B");
  Graph.addDependency("A", "C");
  Graph.addDependency("B", "C");

  // Get dependents of C
  auto Dependents = Graph.getDependents("C");
  EXPECT_EQ(Dependents.size(), 2u);
  EXPECT_TRUE(std::find(Dependents.begin(), Dependents.end(), "A") !=
              Dependents.end());
  EXPECT_TRUE(std::find(Dependents.begin(), Dependents.end(), "B") !=
              Dependents.end());

  // Get dependents of B
  Dependents = Graph.getDependents("B");
  EXPECT_EQ(Dependents.size(), 1u);
  EXPECT_TRUE(std::find(Dependents.begin(), Dependents.end(), "A") !=
              Dependents.end());

  // Get dependents of A
  Dependents = Graph.getDependents("A");
  EXPECT_EQ(Dependents.size(), 0u);
}

TEST(TUDependencyGraphTest, GetAllTUs) {
  TUDependencyGraph Graph;

  // Add dependencies
  Graph.addDependency("A", "B");
  Graph.addDependency("B", "C");

  // Get all TUs
  auto TUs = Graph.getAllTUs();
  EXPECT_EQ(TUs.size(), 3u);
  EXPECT_TRUE(std::find(TUs.begin(), TUs.end(), "A") != TUs.end());
  EXPECT_TRUE(std::find(TUs.begin(), TUs.end(), "B") != TUs.end());
  EXPECT_TRUE(std::find(TUs.begin(), TUs.end(), "C") != TUs.end());
}

TEST(TUDependencyGraphTest, TopologicalSortAcyclic) {
  TUDependencyGraph Graph;

  // Add dependencies for an acyclic graph
  Graph.addDependency("A", "B");
  Graph.addDependency("B", "C");
  Graph.addDependency("A", "C");

  // Perform topological sort
  llvm::SmallVector<PathTy, 16> Result;
  bool IsAcyclic = Graph.topologicalSort(Result);

  // Check that the graph is acyclic
  EXPECT_TRUE(IsAcyclic);

  // Check that the result contains all TUs
  EXPECT_EQ(Result.size(), 3u);
  EXPECT_TRUE(std::find(Result.begin(), Result.end(), "A") != Result.end());
  EXPECT_TRUE(std::find(Result.begin(), Result.end(), "B") != Result.end());
  EXPECT_TRUE(std::find(Result.begin(), Result.end(), "C") != Result.end());

  // Check that dependencies come after their dependents
  auto AIndex = std::find(Result.begin(), Result.end(), "A") - Result.begin();
  auto BIndex = std::find(Result.begin(), Result.end(), "B") - Result.begin();
  auto CIndex = std::find(Result.begin(), Result.end(), "C") - Result.begin();

  EXPECT_LT(AIndex, BIndex);
  EXPECT_LT(BIndex, CIndex);
}

TEST(TUDependencyGraphTest, TopologicalSortCyclic) {
  TUDependencyGraph Graph;

  // Add dependencies for a cyclic graph
  Graph.addDependency("A", "B");
  Graph.addDependency("B", "C");
  Graph.addDependency("C", "A");

  // Perform topological sort
  llvm::SmallVector<PathTy, 16> Result;
  bool IsAcyclic = Graph.topologicalSort(Result);

  // Check that the graph is cyclic
  EXPECT_FALSE(IsAcyclic);

  // Check that the result contains all TUs
  EXPECT_EQ(Result.size(), 3u);
  EXPECT_TRUE(std::find(Result.begin(), Result.end(), "A") != Result.end());
  EXPECT_TRUE(std::find(Result.begin(), Result.end(), "B") != Result.end());
  EXPECT_TRUE(std::find(Result.begin(), Result.end(), "C") != Result.end());
}

TEST(TUDependencyGraphTest, DetectSCCs) {
  TUDependencyGraph Graph;

  // Add dependencies for a graph with multiple SCCs
  Graph.addDependency("A", "B");
  Graph.addDependency("B", "C");
  Graph.addDependency("C", "A"); // Cycle 1: A -> B -> C -> A
  Graph.addDependency("D", "E");
  Graph.addDependency("E", "D"); // Cycle 2: D -> E -> D
  Graph.addDependency("F", "G"); // No cycle

  // Detect SCCs
  auto SCCs = Graph.detectSCCs();

  // Check that we found the correct number of SCCs
  EXPECT_EQ(SCCs.size(), 4u);

  // Find the SCC containing A, B, C
  auto FindSCC = [&SCCs](llvm::StringRef TU) {
    for (const auto &SCC : SCCs) {
      if (std::find(SCC.TUs.begin(), SCC.TUs.end(), TU) != SCC.TUs.end()) {
        return &SCC;
      }
    }
    return static_cast<const StronglyConnectedComponent *>(nullptr);
  };

  const auto *SCC1 = FindSCC("A");
  EXPECT_NE(SCC1, nullptr);
  EXPECT_TRUE(SCC1->IsCyclic);
  EXPECT_EQ(SCC1->TUs.size(), 3u);
  EXPECT_TRUE(std::find(SCC1->TUs.begin(), SCC1->TUs.end(), "A") !=
              SCC1->TUs.end());
  EXPECT_TRUE(std::find(SCC1->TUs.begin(), SCC1->TUs.end(), "B") !=
              SCC1->TUs.end());
  EXPECT_TRUE(std::find(SCC1->TUs.begin(), SCC1->TUs.end(), "C") !=
              SCC1->TUs.end());

  // Find the SCC containing D, E
  const auto *SCC2 = FindSCC("D");
  EXPECT_NE(SCC2, nullptr);
  EXPECT_TRUE(SCC2->IsCyclic);
  EXPECT_EQ(SCC2->TUs.size(), 2u);
  EXPECT_TRUE(std::find(SCC2->TUs.begin(), SCC2->TUs.end(), "D") !=
              SCC2->TUs.end());
  EXPECT_TRUE(std::find(SCC2->TUs.begin(), SCC2->TUs.end(), "E") !=
              SCC2->TUs.end());

  // Find the SCC containing F
  const auto *SCC3 = FindSCC("F");
  EXPECT_NE(SCC3, nullptr);
  EXPECT_FALSE(SCC3->IsCyclic);
  EXPECT_EQ(SCC3->TUs.size(), 1u);
  EXPECT_TRUE(std::find(SCC3->TUs.begin(), SCC3->TUs.end(), "F") !=
              SCC3->TUs.end());

  // Find the SCC containing G
  const auto *SCC4 = FindSCC("G");
  EXPECT_NE(SCC4, nullptr);
  EXPECT_FALSE(SCC4->IsCyclic);
  EXPECT_EQ(SCC4->TUs.size(), 1u);
  EXPECT_TRUE(std::find(SCC4->TUs.begin(), SCC4->TUs.end(), "G") !=
              SCC4->TUs.end());
}
