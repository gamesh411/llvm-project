set(LLVM_LINK_COMPONENTS
  FrontendOpenMP
  Support
  TargetParser
  )

add_clang_library(clangStaticAnalyzerCheckers
  AnalysisOrderChecker.cpp
  AnalyzerStatsChecker.cpp
  ArrayBoundChecker.cpp
  AssumeModeling.cpp
  BasicObjCFoundationChecks.cpp
  BitwiseShiftChecker.cpp
  BlockInCriticalSectionChecker.cpp
  BoolAssignmentChecker.cpp
  BuiltinFunctionChecker.cpp
  CStringChecker.cpp
  CStringSyntaxChecker.cpp
  CallAndMessageChecker.cpp
  CastSizeChecker.cpp
  CastToStructChecker.cpp
  CastValueChecker.cpp
  CheckObjCDealloc.cpp
  CheckObjCInstMethSignature.cpp
  CheckPlacementNew.cpp
  CheckSecuritySyntaxOnly.cpp
  CheckerDocumentation.cpp
  ChrootChecker.cpp
  CloneChecker.cpp
  ContainerModeling.cpp
  ConversionChecker.cpp
  CXXDeleteChecker.cpp
  CXXSelfAssignmentChecker.cpp
  DeadStoresChecker.cpp
  DebugCheckers.cpp
  DebugContainerModeling.cpp
  DebugIteratorModeling.cpp
  DereferenceChecker.cpp
  DirectIvarAssignment.cpp
  DivZeroChecker.cpp
  DynamicTypePropagation.cpp
  DynamicTypeChecker.cpp
  EnumCastOutOfRangeChecker.cpp
  ErrnoChecker.cpp
  ErrnoModeling.cpp
  ErrnoTesterChecker.cpp
  ExprInspectionChecker.cpp
  FixedAddressChecker.cpp
  FuchsiaHandleChecker.cpp
  GCDAntipatternChecker.cpp
  GenericTaintChecker.cpp
  GTestChecker.cpp
  InnerPointerChecker.cpp
  InvalidatedIteratorChecker.cpp
  cert/InvalidPtrChecker.cpp
  Iterator.cpp
  IteratorModeling.cpp
  IteratorRangeChecker.cpp
  IvarInvalidationChecker.cpp
  LLVMConventionsChecker.cpp
  LocalizationChecker.cpp
  MacOSKeychainAPIChecker.cpp
  MacOSXAPIChecker.cpp
  MallocChecker.cpp
  MallocSizeofChecker.cpp
  MismatchedIteratorChecker.cpp
  MmapWriteExecChecker.cpp
  MIGChecker.cpp
  MoveChecker.cpp
  MPI-Checker/MPIBugReporter.cpp
  MPI-Checker/MPIChecker.cpp
  MPI-Checker/MPIFunctionClassifier.cpp
  NSAutoreleasePoolChecker.cpp
  NSErrorChecker.cpp
  NoReturnFunctionChecker.cpp
  NonNullParamChecker.cpp
  NonnullGlobalConstantsChecker.cpp
  NoOwnershipChangeVisitor.cpp
  NullabilityChecker.cpp
  NumberObjectConversionChecker.cpp
  ObjCAtSyncChecker.cpp
  ObjCAutoreleaseWriteChecker.cpp
  ObjCContainersASTChecker.cpp
  ObjCContainersChecker.cpp
  ObjCMissingSuperCallChecker.cpp
  ObjCPropertyChecker.cpp
  ObjCSelfInitChecker.cpp
  ObjCSuperDeallocChecker.cpp
  ObjCUnusedIVarsChecker.cpp
  OSObjectCStyleCast.cpp
  PaddingChecker.cpp
  PointerArithChecker.cpp
  PointerSubChecker.cpp
  PthreadLockChecker.cpp
  PutenvStackArrayChecker.cpp
  RetainCountChecker/RetainCountChecker.cpp
  RetainCountChecker/RetainCountDiagnostics.cpp
  ReturnPointerRangeChecker.cpp
  ReturnUndefChecker.cpp
  ReturnValueChecker.cpp
  RunLoopAutoreleaseLeakChecker.cpp
  SetgidSetuidOrderChecker.cpp
  SimpleStreamChecker.cpp
  SmartPtrChecker.cpp
  SmartPtrModeling.cpp
  StackAddrEscapeChecker.cpp
  StoreToImmutableChecker.cpp
  StdLibraryFunctionsChecker.cpp
  StdVariantChecker.cpp
  STLAlgorithmModeling.cpp
  StreamChecker.cpp
  EmbeddedDSLMonitorChecker.cpp
  EmbeddedDSLSpot.cpp
  StringChecker.cpp
  Taint.cpp
  TaintTesterChecker.cpp
  TestAfterDivZeroChecker.cpp
  TraversalChecker.cpp
  TrustNonnullChecker.cpp
  TrustReturnsNonnullChecker.cpp
  UndefBranchChecker.cpp
  UndefCapturedBlockVarChecker.cpp
  UndefResultChecker.cpp
  UndefinedArraySubscriptChecker.cpp
  UndefinedAssignmentChecker.cpp
  UndefinedNewArraySizeChecker.cpp
  UninitializedObject/UninitializedObjectChecker.cpp
  UninitializedObject/UninitializedPointee.cpp
  UnixAPIChecker.cpp
  UnreachableCodeChecker.cpp
  VforkChecker.cpp
  VLASizeChecker.cpp
  ValistChecker.cpp
  VirtualCallChecker.cpp
  WebKit/ASTUtils.cpp
  WebKit/ForwardDeclChecker.cpp
  WebKit/MemoryUnsafeCastChecker.cpp
  WebKit/PtrTypesSemantics.cpp
  WebKit/RefCntblBaseVirtualDtorChecker.cpp
  WebKit/RetainPtrCtorAdoptChecker.cpp
  WebKit/RawPtrRefCallArgsChecker.cpp
  WebKit/RawPtrRefLambdaCapturesChecker.cpp
  WebKit/RawPtrRefLocalVarsChecker.cpp
  WebKit/RawPtrRefMemberChecker.cpp

  LINK_LIBS
  clangAST
  clangASTMatchers
  clangAnalysis
  clangBasic
  clangLex
  clangStaticAnalyzerCore

  DEPENDS
  omp_gen
  ClangDriverOptions
  )

# Mark that this target intentionally does not list all sources in some configs
set_property(TARGET clangStaticAnalyzerCheckers PROPERTY PARTIAL_SOURCES_INTENDED TRUE)

# Unconditionally use SPOT-backed monitor. If SPOT is not available,
# EmbeddedDSLSpot.cpp should include guards or vendors minimal subset.
find_path(SPOT_INCLUDE_DIR spot/tl/formula.hh
  HINTS
    /opt/homebrew/include
    /usr/local/include
    /opt/local/include
)
find_path(SPOT_TRANSLATE_HEADER_DIR spot/twaalgos/translate.hh
  HINTS
    /opt/homebrew/include
    /usr/local/include
    /opt/local/include
)
find_library(SPOT_LIB NAMES spot libspot
  HINTS
    /opt/homebrew/lib
    /usr/local/lib
    /opt/local/lib
)
if (NOT SPOT_INCLUDE_DIR OR NOT SPOT_LIB OR NOT SPOT_TRANSLATE_HEADER_DIR)
  message(FATAL_ERROR "SPOT not found or incomplete (need spot/tl/formula.hh and spot/twaalgos/translate.hh). Install SPOT and set SPOT_INCLUDE_DIR/SPOT_LIB.")
endif()

target_include_directories(clangStaticAnalyzerCheckers PRIVATE ${SPOT_INCLUDE_DIR})
target_link_libraries(clangStaticAnalyzerCheckers PRIVATE ${SPOT_LIB})

# SPOT headers use exceptions in inline code; enable exceptions for this TU
set_source_files_properties(EmbeddedDSLSpot.cpp PROPERTIES COMPILE_FLAGS "-fexceptions")
