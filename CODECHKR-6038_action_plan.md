# CODECHKR-6038 Action Plan: StoreToImmutable and ModelConstQualifiedReturn Checkers

## Overview
This document outlines the plan to implement the Jira ticket CODECHKR-6038, which involves upstreaming the changes from Phabricator patch D124244. The goal is to add two new static analyzer checkers:

1. **core.StoreToImmutable** - Warns about writes to immutable memory
2. **alpha.security.cert.env.ModelConstQualifiedReturn** - Models return values of certain functions as const-qualified

These checkers implement SEI CERT Rule ENV30-C: https://wiki.sei.cmu.edu/confluence/x/79UxBQ

## Current State Analysis

### ✅ Already Available
- `GlobalImmutableSpaceRegion` class exists in `MemRegion.h`
- `InvalidPtrChecker` exists and handles some environment variable functions (ENV31-C, ENV34-C)
- Basic infrastructure for static analyzer checkers is in place

### ❌ Missing (Need to Implement)
- `StoreToImmutableChecker` implementation
- `ModelConstQualifiedReturnChecker` implementation
- Checker registrations in `Checkers.td`
- CMake build system integration
- Documentation updates
- Test cases

## Implementation Plan - Upstreamable Chunks

Based on analysis of the diff and dependencies, the implementation should be split into **3 logical chunks** for easy upstreaming and review:

### Chunk 1: Core Infrastructure and StoreToImmutable Checker (Independent) ✅ **COMPLETED**
**Purpose**: Implement the foundational infrastructure and the core StoreToImmutable checker that can work independently.

**Files to modify/create**:
- [x] **Task 1.1**: Update `MemRegion.h` assertion
  - File: `clang/include/clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h`
  - Line: ~821 (assert statement)
  - Change: Add `GlobalImmutableSpaceRegion` to the assertion

- [x] **Task 1.2**: ~~Create `StoreToImmutable.h` header~~ (Simplified - removed shared header)
  - ~~File: `clang/lib/StaticAnalyzer/Checkers/StoreToImmutable.h`~~
  - ~~Purpose: Expose `ImmutableMemoryBind` BugType for other checkers~~

- [x] **Task 1.3**: Implement `StoreToImmutableChecker.cpp`
  - File: `clang/lib/StaticAnalyzer/Checkers/StoreToImmutableChecker.cpp`
  - Features:
    - Checker for `check::Bind` events
    - Detects writes to `GlobalImmutableSpaceRegion`
    - Generates appropriate bug reports
    - Tracks expression values for better diagnostics

- [x] **Task 1.4**: Register StoreToImmutable checker
  - File: `clang/include/clang/StaticAnalyzer/Checkers/Checkers.td`
  - Add: `StoreToImmutableChecker` definition

- [x] **Task 1.5**: Update CMake build
  - File: `clang/lib/StaticAnalyzer/Checkers/CMakeLists.txt`
  - Add: `StoreToImmutableChecker.cpp` to build

- [x] **Task 1.6**: Basic tests for StoreToImmutable
  - File: `clang/test/Analysis/store-to-immutable-basic.cpp`
  - Test: Direct writes to immutable regions (without function modeling)

**Status**: ✅ **COMPLETED** - Committed as `a6feb2401b41`
**Dependencies**: None - this chunk is self-contained
**Review Focus**: Core checker logic, memory region handling, bug reporting

### Chunk 2: ModelConstQualifiedReturn Checker (Depends on Chunk 1)
**Purpose**: Implement the function modeling checker that creates immutable regions for specific function return values.

**Files to modify/create**:
- [ ] **Task 2.1**: Implement `ModelConstQualifiedReturnChecker.cpp`
  - File: `clang/lib/StaticAnalyzer/Checkers/cert/ModelConstQualifiedReturnChecker.cpp`
  - Features:
    - Models return values of specific functions as const-qualified
    - Functions: `getenv()`, `setlocale()`, `localeconv()`, `asctime()`, `strerror()`
    - Uses `check::PostCall` callback
    - Creates symbolic regions in `GlobalImmutableSpaceRegion`
    - Adds note tags for better diagnostics

- [ ] **Task 2.2**: Register ModelConstQualifiedReturn checker
  - File: `clang/include/clang/StaticAnalyzer/Checkers/Checkers.td`
  - Add: `ModelConstQualifiedReturnChecker` definition under `alpha.cert.env`

- [ ] **Task 2.3**: Update CMake build
  - File: `clang/lib/StaticAnalyzer/Checkers/CMakeLists.txt`
  - Add: `cert/ModelConstQualifiedReturnChecker.cpp` to build

- [ ] **Task 2.4**: Integration tests
  - File: `clang/test/Analysis/cert/env30-c.cpp`
  - Test: Function modeling + StoreToImmutable interaction

**Dependencies**: Chunk 1 (checker infrastructure)
**Review Focus**: Function modeling logic, cross-checker communication, CERT compliance

### Chunk 3: Documentation and Test Updates (Depends on Chunks 1 & 2)
**Purpose**: Complete the implementation with documentation and comprehensive test coverage.

**Files to modify**:
- [ ] **Task 3.1**: Update documentation
  - File: `clang/docs/analyzer/checkers.rst`
  - Add: Documentation for `core.StoreToImmutable`
  - Add: Documentation for `alpha.security.cert.env.ModelConstQualifiedReturn`
  - Include examples and usage instructions

- [ ] **Task 3.2**: Update existing test files
  - File: `clang/test/Analysis/analyzer-enabled-checkers.c`
  - File: `clang/test/Analysis/std-c-library-functions-arg-enabled-checkers.c`
  - Add: New checkers to expected output lists

- [ ] **Task 3.3**: Comprehensive test suite expansion
  - File: `clang/test/Analysis/cert/env30-c.cpp` (expand existing)
  - Test cases:
    - All function types (`getenv`, `setlocale`, `strerror`, `asctime`, `localeconv`)
    - Compliant vs non-compliant code examples
    - Edge cases and null pointer handling
    - Function call chains and parameter passing
    - Integration with existing checkers

**Dependencies**: Chunks 1 & 2 (all functionality must be implemented)
**Review Focus**: Documentation quality, test coverage, integration completeness

## Chunking Rationale

### Why 3 Chunks Instead of 2?
The original ticket suggested 2 PRs, but analysis shows **3 chunks are optimal**:

1. **Chunk 1** provides independent value - the StoreToImmutable checker can detect immutable memory writes even without function modeling
2. **Chunk 2** builds on Chunk 1 and adds the CERT-specific function modeling
3. **Chunk 3** completes the implementation with docs and comprehensive tests

### Benefits of This Approach:
- **Incremental Value**: Each chunk provides immediate, testable functionality
- **Easier Review**: Smaller, focused changes are easier to review thoroughly
- **Risk Mitigation**: Issues in later chunks don't block earlier functionality
- **Testing**: Each chunk can be tested independently
- **Rollback**: If issues arise, earlier chunks can remain while later ones are fixed

### Alternative: 2-Chunk Approach
If 3 chunks are too many, we could combine Chunks 1 & 2, but this would:
- Make the PR larger and harder to review
- Reduce the ability to test components independently
- Increase risk if issues are found in the function modeling logic

## Technical Debt Considerations

### Issue from Original Ticket
The ticket mentions a technical issue: "the checker rebinds the return value in a `check::PostCall` callback – which should only happen in `eval::Call`"

**Analysis**: The `ModelConstQualifiedReturnChecker` uses `check::PostCall` to rebind function return values to immutable regions. This is technically incorrect because:
- `check::PostCall` is for post-processing after a call is evaluated
- `eval::Call` is for custom evaluation of function calls
- Rebinding return values should happen during evaluation, not after

**Proposed Solutions**:
1. **Option A**: Move the rebinding logic to `eval::Call` (recommended)
   - More technically correct
   - May require more complex implementation
   - Better integration with the analysis engine

2. **Option B**: Keep current approach but document the limitation
   - Simpler implementation
   - May cause issues with certain analysis scenarios
   - Should be clearly documented as a known limitation

**Recommendation**: Implement Option A in Chunk 2, as it's the technically correct approach and will prevent future issues.

## Technical Considerations

### Architecture Decisions
1. **Separation of Concerns**: 
   - `StoreToImmutableChecker` handles the core detection logic
   - `ModelConstQualifiedReturnChecker` handles function modeling
   - Clear interface between them via `StoreToImmutable.h`

2. **Memory Region Strategy**:
   - Use existing `GlobalImmutableSpaceRegion` infrastructure
   - Leverage symbolic region creation for function return values
   - Ensure proper region management

3. **Checker Interaction**:
   - `ModelConstQualifiedReturnChecker` creates immutable regions
   - `StoreToImmutableChecker` detects modifications to these regions
   - Each checker has its own bug type for independence

### Potential Challenges
1. **Performance**: Ensure checkers don't significantly impact analysis speed
2. **False Positives**: Balance detection accuracy with usability
3. **Integration**: Ensure smooth integration with existing checkers
4. **Backward Compatibility**: Don't break existing functionality

## Success Criteria
- [ ] All test cases pass for each chunk
- [ ] No performance regression in static analysis
- [ ] Clear, actionable diagnostic messages
- [ ] Proper integration with existing CERT checkers
- [ ] Documentation is complete and accurate
- [ ] Code review feedback is addressed
- [ ] Technical debt from original implementation is resolved

## Next Steps

### ✅ Chunk 1 Completed (December 2024)
- **Status**: Successfully implemented and committed
- **Commit**: `a6feb2401b41` - "[analyzer] Add StoreToImmutable checker"
- **Files**: 7 files modified, 3 new files created
- **Functionality**: Core StoreToImmutable checker with comprehensive test coverage

### 🎯 Next Priority: Chunk 2 - ModelConstQualifiedReturn Checker
**Ready to start immediately** - all dependencies from Chunk 1 are complete.

**Key Technical Challenge**: The original implementation has a technical debt issue where it uses `check::PostCall` to rebind return values, but this should happen in `eval::Call` instead. This will be addressed in the implementation.

**Implementation Plan**:
1. **Create the checker file** in `clang/lib/StaticAnalyzer/Checkers/cert/ModelConstQualifiedReturnChecker.cpp`
2. **Fix the technical debt** by using `eval::Call` instead of `check::PostCall` for rebinding return values
3. **Register the checker** in `Checkers.td` under `alpha.cert.env` namespace
4. **Update CMake build** to include the new checker
5. **Create integration tests** that demonstrate the interaction between both checkers

**Functions to model as const-qualified** (from CERT ENV30-C):
- `getenv()` - environment variable access
- `setlocale()` - locale setting
- `localeconv()` - locale conversion
- `asctime()` - time formatting
- `strerror()` - error message formatting

**Expected Behavior**: When these functions are called, their return values should be modeled as residing in `GlobalImmutableSpaceRegion`, which will then trigger the `StoreToImmutableChecker` when attempts are made to modify them.

## Timeline Estimate by Chunk

### Chunk 1: Core Infrastructure and StoreToImmutable Checker ✅ **COMPLETED**
- **Implementation**: 2-3 days ✅
- **Testing**: 1-2 days ✅
- **Review & Iteration**: 1-2 days ✅
- **Total**: 4-7 days ✅

### Chunk 2: ModelConstQualifiedReturn Checker 🎯 **NEXT**
- **Implementation**: 2-3 days (including technical debt fix)
- **Testing**: 1-2 days
- **Review & Iteration**: 1-2 days
- **Total**: 4-7 days

### Chunk 3: Documentation and Test Updates
- **Implementation**: 1-2 days
- **Testing**: 1 day
- **Review & Iteration**: 1 day
- **Total**: 3-4 days

**Total Estimated Time**: 11-18 days (sequential)
**Parallel Development**: Chunks 1 & 2 could be developed in parallel after Chunk 1 is reviewed

## Notes
- The original patch was from April 2023 and needs to be updated for current codebase
- The implementation will be split into 3 upstreamable chunks for easier review
- Technical debt from the original implementation (PostCall vs eval::Call) will be addressed
- Each chunk provides independent value and can be tested separately
- Ensure compliance with LLVM coding standards and review processes
- Consider the relationship with existing `InvalidPtrChecker` to avoid duplication 