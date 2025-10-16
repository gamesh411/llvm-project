# Refactoring Plan: Add Initialization vs Assignment Distinction to checkBind API

## Current State

Currently, the `checkBind` callback has this signature:
```cpp
void checkBind(SVal location, SVal val, const Stmt *S, CheckerContext &C) const;
```

The `atDeclInit` parameter is available in `ExprEngine::evalBind()` but is not passed through to the checkers.

## Proposed Changes

### 1. Update Function Type Definition

**File**: `clang/include/clang/StaticAnalyzer/Core/CheckerManager.h`
**Line**: 501-502

**Current**:
```cpp
using CheckBindFunc =
    CheckerFn<void(SVal location, SVal val, const Stmt *S, CheckerContext &)>;
```

**Proposed**:
```cpp
using CheckBindFunc =
    CheckerFn<void(SVal location, SVal val, const Stmt *S, bool isInit, CheckerContext &)>;
```

### 2. Update Checker Registration

**File**: `clang/include/clang/StaticAnalyzer/Core/Checker.h`
**Lines**: 210-219

**Current**:
```cpp
template <typename CHECKER>
static void _checkBind(void *checker, SVal location, SVal val, const Stmt *S,
                       CheckerContext &C) {
  ((const CHECKER *)checker)->checkBind(location, val, S, C);
}
```

**Proposed**:
```cpp
template <typename CHECKER>
static void _checkBind(void *checker, SVal location, SVal val, const Stmt *S,
                       bool isInit, CheckerContext &C) {
  ((const CHECKER *)checker)->checkBind(location, val, S, isInit, C);
}
```

### 3. Update CheckBindContext

**File**: `clang/lib/StaticAnalyzer/Core/CheckerManager.cpp`
**Lines**: 370-395

**Current**:
```cpp
struct CheckBindContext {
  using CheckersTy = std::vector<CheckerManager::CheckBindFunc>;

  const CheckersTy &Checkers;
  SVal Loc;
  SVal Val;
  const Stmt *S;
  ExprEngine &Eng;
  const ProgramPoint &PP;

  CheckBindContext(const CheckersTy &checkers,
                   SVal loc, SVal val, const Stmt *s, ExprEngine &eng,
                   const ProgramPoint &pp)
      : Checkers(checkers), Loc(loc), Val(val), S(s), Eng(eng), PP(pp) {}

  void runChecker(CheckerManager::CheckBindFunc checkFn,
                  NodeBuilder &Bldr, ExplodedNode *Pred) {
    llvm::TimeTraceScope TimeScope(checkerScopeName("Bind", checkFn.Checker));
    const ProgramPoint &L = PP.withTag(checkFn.Checker);
    CheckerContext C(Bldr, Eng, Pred, L);

    checkFn(Loc, Val, S, C);
  }
};
```

**Proposed**:
```cpp
struct CheckBindContext {
  using CheckersTy = std::vector<CheckerManager::CheckBindFunc>;

  const CheckersTy &Checkers;
  SVal Loc;
  SVal Val;
  const Stmt *S;
  bool IsInit;
  ExprEngine &Eng;
  const ProgramPoint &PP;

  CheckBindContext(const CheckersTy &checkers,
                   SVal loc, SVal val, const Stmt *s, bool isInit,
                   ExprEngine &eng, const ProgramPoint &pp)
      : Checkers(checkers), Loc(loc), Val(val), S(s), IsInit(isInit),
        Eng(eng), PP(pp) {}

  void runChecker(CheckerManager::CheckBindFunc checkFn,
                  NodeBuilder &Bldr, ExplodedNode *Pred) {
    llvm::TimeTraceScope TimeScope(checkerScopeName("Bind", checkFn.Checker));
    const ProgramPoint &L = PP.withTag(checkFn.Checker);
    CheckerContext C(Bldr, Eng, Pred, L);

    checkFn(Loc, Val, S, IsInit, C);
  }
};
```

### 4. Update runCheckersForBind Function

**File**: `clang/lib/StaticAnalyzer/Core/CheckerManager.cpp`
**Lines**: 408-415

**Current**:
```cpp
void CheckerManager::runCheckersForBind(ExplodedNodeSet &Dst,
                                        const ExplodedNodeSet &Src,
                                        SVal location, SVal val,
                                        const Stmt *S, ExprEngine &Eng,
                                        const ProgramPoint &PP) {
  CheckBindContext C(BindCheckers, location, val, S, Eng, PP);
  // ...
}
```

**Proposed**:
```cpp
void CheckerManager::runCheckersForBind(ExplodedNodeSet &Dst,
                                        const ExplodedNodeSet &Src,
                                        SVal location, SVal val,
                                        const Stmt *S, bool isInit,
                                        ExprEngine &Eng,
                                        const ProgramPoint &PP) {
  CheckBindContext C(BindCheckers, location, val, S, isInit, Eng, PP);
  // ...
}
```

### 5. Update Function Declaration

**File**: `clang/include/clang/StaticAnalyzer/Core/CheckerManager.h`
**Line**: 341

**Current**:
```cpp
void runCheckersForBind(ExplodedNodeSet &Dst,
                        const ExplodedNodeSet &Src,
                        SVal location, SVal val,
                        const Stmt *S, ExprEngine &Eng,
                        const ProgramPoint &PP);
```

**Proposed**:
```cpp
void runCheckersForBind(ExplodedNodeSet &Dst,
                        const ExplodedNodeSet &Src,
                        SVal location, SVal val,
                        const Stmt *S, bool isInit,
                        ExprEngine &Eng,
                        const ProgramPoint &PP);
```

### 6. Update evalBind Call Site

**File**: `clang/lib/StaticAnalyzer/Core/ExprEngine.cpp`
**Line**: 3726

**Current**:
```cpp
getCheckerManager().runCheckersForBind(CheckedSet, Pred, location, Val,
                                       StoreE, *this, *PP);
```

**Proposed**:
```cpp
getCheckerManager().runCheckersForBind(CheckedSet, Pred, location, Val,
                                       StoreE, atDeclInit, *this, *PP);
```

## Implementation Steps

1. **Update header files** (Checker.h, CheckerManager.h)
2. **Update implementation files** (CheckerManager.cpp, ExprEngine.cpp)
3. **Update all existing checkers** to use the new signature
4. **Add tests** to verify the new functionality

## Benefits

1. **Better API**: Checkers can now distinguish between initializations and assignments
2. **More precise analysis**: Checkers can apply different logic for different types of bindings
3. **Backward compatibility**: Existing checkers will need to be updated but the change is straightforward
4. **Future-proof**: The API now provides more information to checkers

## Example Usage

After the refactoring, checkers can use the new API like this:

```cpp
void MyChecker::checkBind(SVal location, SVal val, const Stmt *S, 
                         bool isInit, CheckerContext &C) const {
  if (isInit) {
    // Handle initialization
    // e.g., int x = 42;
  } else {
    // Handle assignment
    // e.g., x = 100;
  }
}
```

## Files to Modify

1. `clang/include/clang/StaticAnalyzer/Core/Checker.h`
2. `clang/include/clang/StaticAnalyzer/Core/CheckerManager.h`
3. `clang/lib/StaticAnalyzer/Core/CheckerManager.cpp`
4. `clang/lib/StaticAnalyzer/Core/ExprEngine.cpp`
5. All existing checkers that implement `checkBind` 