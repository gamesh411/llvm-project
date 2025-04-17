set(LLVM_LINK_COMPONENTS
  Support
  Core
)

add_clang_library(clangExceptionScan
  CollectExceptionInfo.cpp
  ExceptionAnalyzer.cpp
  CallGraphGeneratorConsumer.cpp
  USRMappingConsumer.cpp
  NoexceptDependeeConsumer.cpp
  PARTIAL_SOURCES_INTENDED
  LINK_LIBS
  clangAST
  clangASTMatchers
  clangAnalysis
  clangBasic
  clangCrossTU
  clangFrontend
  clangTooling
  clangIndex
)

install(FILES
  ExceptionAnalyzer.h
  CollectExceptionInfo.h
  Serialization.h
  CallGraphGeneratorConsumer.h
  USRMappingConsumer.h
  NoexceptDependeeConsumer.h
  GlobalExceptionInfo.h
  DESTINATION include/clang/Tooling/clang-exception-scan
)

add_clang_tool(clang-exception-scan
  ClangExceptionScan.cpp
  PARTIAL_SOURCES_INTENDED
)

target_link_libraries(clang-exception-scan
  PRIVATE
  clangCrossTU
  clangExceptionScan
  clangTooling
  clangBasic
  clangAST
  clangASTMatchers
  clangFrontend
  clangSerialization
)

# Add the example tool
add_clang_tool(clang-exception-analyzer-example
  ExceptionAnalyzerExample.cpp
  PARTIAL_SOURCES_INTENDED
)

target_link_libraries(clang-exception-analyzer-example
  PRIVATE
  clangExceptionScan
  clangTooling
  clangBasic
  clangAST
  clangASTMatchers
  clangFrontend
  clangSerialization
)
