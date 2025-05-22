#include "TUDependencyGraph.h"
#include "llvm/Support/raw_ostream.h"
#include <map>

namespace clang {
namespace exception_scan {

bool TUDependencyGraph::addIndependentTU(llvm::StringRef TU) {
  std::lock_guard<std::mutex> Lock(GraphMutex);
  return AdjacencyList.insert(std::make_pair(TU, llvm::StringSet<>())).second;
}

bool TUDependencyGraph::addDependency(llvm::StringRef From,
                                      llvm::StringRef To) {
  // Add both TUs to the graph if they don't exist
  bool Modified = false;
  Modified |= addIndependentTU(From);
  Modified |= addIndependentTU(To);

  // Add the dependency
  std::lock_guard<std::mutex> Lock(GraphMutex);
  const auto Result = AdjacencyList[From].insert(To);
  Modified |= Result.second;
  return Modified;
}

bool TUDependencyGraph::hasDependency(llvm::StringRef From,
                                      llvm::StringRef To) const {
  std::lock_guard<std::mutex> Lock(GraphMutex);

  auto It = AdjacencyList.find(From);
  if (It == AdjacencyList.end()) {
    return false;
  }

  return It->second.count(To);
}

llvm::SmallVector<PathTy, 4>
TUDependencyGraph::getDependencies(llvm::StringRef TU) const {
  std::lock_guard<std::mutex> Lock(GraphMutex);

  llvm::SmallVector<PathTy, 4> Result;
  auto It = AdjacencyList.find(TU);
  if (It != AdjacencyList.end()) {
    for (const auto &Dep : It->second) {
      Result.push_back(Dep.getKey());
    }
  }

  return Result;
}

llvm::SmallVector<PathTy, 4>
TUDependencyGraph::getDependents(llvm::StringRef TU) const {
  std::lock_guard<std::mutex> Lock(GraphMutex);

  llvm::SmallVector<PathTy, 4> Result;
  for (const auto &Entry : AdjacencyList) {
    if (Entry.second.count(TU)) {
      Result.push_back(Entry.getKey());
    }
  }

  return Result;
}

llvm::SmallVector<PathTy, 4> TUDependencyGraph::getAllTUs() const {
  std::lock_guard<std::mutex> Lock(GraphMutex);

  llvm::SmallVector<PathTy, 4> Result;
  for (const auto &Entry : AdjacencyList) {
    Result.push_back(Entry.getKey());
  }

  return Result;
}

void TUDependencyGraph::clear() {
  std::lock_guard<std::mutex> Lock(GraphMutex);
  AdjacencyList.clear();
}

bool TUDependencyGraph::topologicalSort(
    llvm::SmallVectorImpl<PathTy> &Result) const {
  std::lock_guard<std::mutex> Lock(GraphMutex);

  // Kahn's algorithm for topological sorting
  std::map<PathTy, unsigned> InDegree;
  llvm::SmallVector<PathTy, 16> Queue;
  bool HasCycle = false;

  // Initialize in-degree for all TUs
  for (const auto &Entry : AdjacencyList) {
    InDegree[Entry.getKey()] = 0;
  }

  // Calculate in-degree for all TUs
  for (const auto &Entry : AdjacencyList) {
    for (const auto &Dep : Entry.second) {
      InDegree[Dep.getKey()]++;
    }
  }

  // Add all TUs with in-degree 0 to the queue
  for (const auto &Entry : InDegree) {
    if (Entry.second == 0) {
      Queue.push_back(Entry.first);
    }
  }

  // Process the queue
  while (!Queue.empty()) {
    PathTy Current = Queue.pop_back_val();
    Result.push_back(Current);

    // Decrease in-degree for all dependencies
    auto It = AdjacencyList.find(Current);
    if (It != AdjacencyList.end()) {
      for (const auto &Dep : It->second) {
        InDegree[Dep.getKey()]--;
        if (InDegree[Dep.getKey()] == 0) {
          Queue.push_back(Dep.getKey());
        }
      }
    }
  }

  // Check if we have a cycle
  for (const auto &Entry : InDegree) {
    if (Entry.second > 0) {
      HasCycle = true;
      break;
    }
  }

  // Add remaining TUs that are part of cycles
  for (const auto &Entry : InDegree) {
    if (Entry.second > 0) {
      Result.push_back(Entry.first);
    }
  }

  return !HasCycle; // Return true if acyclic, false if cyclic
}

void TUDependencyGraph::tarjanDFS(
    llvm::StringRef TU, llvm::StringMap<unsigned> &Index,
    llvm::StringMap<unsigned> &LowLink, llvm::SmallVectorImpl<PathTy> &Stack,
    llvm::StringSet<> &OnStack, unsigned &CurrentIndex,
    llvm::SmallVector<StronglyConnectedComponent, 4> &SCCs) const {

  // Set the index and low link for the current TU
  Index[TU] = CurrentIndex;
  LowLink[TU] = CurrentIndex;
  CurrentIndex++;

  // Add the current TU to the stack and mark it as being on the stack
  Stack.push_back(TU);
  OnStack.insert(TU);

  // Process all dependencies of the current TU
  auto It = AdjacencyList.find(TU);
  if (It != AdjacencyList.end()) {
    for (const auto &Dep : It->second) {
      const PathTy Neighbor = Dep.getKey();

      // If the neighbor has not been visited yet, recursively call tarjanDFS
      if (!Index.count(Neighbor)) {
        tarjanDFS(Neighbor, Index, LowLink, Stack, OnStack, CurrentIndex, SCCs);
        LowLink[TU] = std::min(LowLink[TU], LowLink[Neighbor]);
      }
      // If the neighbor is already on the stack, update the low link of the
      // current TU
      else if (OnStack.count(Neighbor)) {
        LowLink[TU] = std::min(LowLink[TU], Index[Neighbor]);
      }
    }
  }

  // If the low link of the current TU is equal to its index, we have found an
  // SCC
  if (LowLink[TU] == Index[TU]) {
    StronglyConnectedComponent SCC;
    SCC.IsCyclic = false;

    // Pop TUs from the stack until we reach the current TU
    PathTy PoppedTU;
    do {
      PoppedTU = Stack.pop_back_val();
      OnStack.erase(PoppedTU);
      SCC.TUs.push_back(PoppedTU);
    } while (PoppedTU != TU);

    // Check if the SCC is cyclic (has more than one TU or has a self-loop)
    if (SCC.TUs.size() > 1) {
      SCC.IsCyclic = true;
    } else {
      auto SelfIt = AdjacencyList.find(TU);
      if (SelfIt != AdjacencyList.end() && SelfIt->second.count(TU)) {
        SCC.IsCyclic = true;
      }
    }

    SCCs.push_back(std::move(SCC));
  }
}

llvm::SmallVector<StronglyConnectedComponent, 4>
TUDependencyGraph::detectSCCs() const {
  std::lock_guard<std::mutex> Lock(GraphMutex);

  llvm::SmallVector<StronglyConnectedComponent, 4> SCCs;
  llvm::StringMap<unsigned> Index;
  llvm::StringMap<unsigned> LowLink;
  llvm::SmallVector<PathTy, 16> Stack;
  llvm::StringSet<> OnStack;
  unsigned CurrentIndex = 0;

  // Run Tarjan's algorithm for each unvisited TU
  for (const auto &Entry : AdjacencyList) {
    if (!Index.count(Entry.getKey())) {
      tarjanDFS(Entry.getKey(), Index, LowLink, Stack, OnStack, CurrentIndex,
                SCCs);
    }
  }

  return SCCs;
}

} // namespace exception_scan
} // namespace clang