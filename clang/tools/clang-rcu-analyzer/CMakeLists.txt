set(LLVM_LINK_COMPONENTS
  support
  )

add_clang_tool(clang-rcu-analyzer
  ClangRCUAnalyzer.cpp
)

clang_target_link_libraries(clang-rcu-analyzer
  PRIVATE
  clangAST
  clangASTMatchers
  clangBasic
  clangLex
  clangAnalysisFlowSensitive
  clangAnalysis
  clangFrontend
  clangSerialization
  clangTooling
)


