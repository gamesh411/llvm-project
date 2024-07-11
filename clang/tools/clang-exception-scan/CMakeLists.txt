set(LLVM_LINK_COMPONENTS
  ${LLVM_TARGETS_TO_BUILD}
  Support
  FrontendOpenMP # for astmatchers
  )

add_clang_tool(clang-exception-scan
  ClangExceptionScan.cpp
  )

clang_target_link_libraries(clang-exception-scan
  PRIVATE
  clangAST
  clangASTMatchers
  clangAnalysis
  clangBasic
  clangCrossTU
  clangFrontend
  clangSerialization
  clangTooling
  )
