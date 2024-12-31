set(LLVM_LINK_COMPONENTS
  Support
  Core
)

add_clang_library(clangExceptionScan
  CollectExceptionInfo.cpp
  PARTIAL_SOURCES_INTENDED
  LINK_LIBS
  clangAST
  clangASTMatchers
  clangAnalysis
  clangBasic
  clangCrossTU
  clangFrontend
  clangTooling
)

add_clang_tool(clang-exception-scan
  ClangExceptionScan.cpp
  PARTIAL_SOURCES_INTENDED
)

target_link_libraries(clang-exception-scan
  PRIVATE
  clangExceptionScan
  clangTooling
  clangBasic
  clangAST
  clangFrontend
  clangSerialization
)
