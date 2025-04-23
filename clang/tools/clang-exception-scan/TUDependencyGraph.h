#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_TU_DEPENDENCY_GRAPH_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_TU_DEPENDENCY_GRAPH_H

#include "CommonTypes.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"

#include <mutex>
#include <string>

namespace clang {
namespace exception_scan {

/// Represents a strongly connected component (SCC) in the dependency graph
struct StronglyConnectedComponent {
  llvm::SmallVector<PathTy, 4> TUs; ///< TUs in this SCC
  bool IsCyclic;                    ///< Whether this SCC contains cycles
};

/// A graph representing dependencies between translation units
class TUDependencyGraph {
public:
  /// Add a dependency from one TU to another
  void addDependency(llvm::StringRef From, llvm::StringRef To);

  /// Check if a dependency exists
  bool hasDependency(llvm::StringRef From, llvm::StringRef To) const;

  /// Get all dependencies of a TU
  llvm::SmallVector<PathTy, 4> getDependencies(llvm::StringRef TU) const;

  /// Get all TUs that depend on a given TU
  llvm::SmallVector<PathTy, 4> getDependents(llvm::StringRef TU) const;

  /// Get all TUs in the graph
  llvm::SmallVector<PathTy, 4> getAllTUs() const;

  /// Detect strongly connected components in the graph
  llvm::SmallVector<StronglyConnectedComponent, 4> detectSCCs() const;

  /// Perform a topological sort of the TUs
  /// Returns true if the graph is acyclic, false if it contains cycles
  bool topologicalSort(llvm::SmallVectorImpl<PathTy> &Result) const;

  /// Clear all dependencies
  void clear();

private:
  /// The adjacency list representation of the graph
  llvm::StringMap<llvm::StringSet<>> AdjacencyList;

  /// Mutex for thread safety
  mutable std::mutex GraphMutex;

  /// Helper function for Tarjan's algorithm to find SCCs
  void tarjanDFS(llvm::StringRef TU, llvm::StringMap<unsigned> &Index,
                 llvm::StringMap<unsigned> &LowLink,
                 llvm::SmallVectorImpl<PathTy> &Stack,
                 llvm::StringSet<> &OnStack, unsigned &CurrentIndex,
                 llvm::SmallVector<StronglyConnectedComponent, 4> &SCCs) const;
};

} // namespace exception_scan
} // namespace clang

#endif // LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_TU_DEPENDENCY_GRAPH_H