#include "CallGraphGeneratorConsumer.h"
#include "GlobalExceptionInfo.h"
#include "gtest/gtest.h"

#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Tooling/CompilationDatabase.h"
#include "clang/Tooling/Tooling.h"

#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

using namespace clang;
using namespace clang::exception_scan;
using namespace clang::tooling;

namespace {

// Test fixture for call graph generator tests
class CallGraphGeneratorTest : public ::testing::Test {
protected:
  void SetUp() override {
    GEI.USRToFunctionMap.clear();
    GEI.TUToUSRMap.clear();
    GEI.USRToDefinedInTUMap.clear();
    GEI.CallDependencies.clear();
    GEI.TUDependencies.clear();
  }

  GlobalExceptionInfo GEI;

  // Helper function to run the tool on a single file
  void runToolOnCode(const std::string &Code, const std::string &FileName) {
    std::vector<std::string> Args = {"-std=c++17", "-fsyntax-only"};

    // Create a fixed compilation database
    std::string BuildDir = ".";
    auto Compilations =
        std::make_unique<FixedCompilationDatabase>(BuildDir, Args);

    // Create a clang tool and run it
    ClangTool Tool(*Compilations, {FileName});

    // Write the code to a temporary file
    std::error_code EC;
    llvm::raw_fd_ostream OS(FileName, EC, llvm::sys::fs::OF_None);
    if (EC) {
      llvm::errs() << "Error: " << EC.message() << "\n";
      return;
    }
    OS << Code;
    OS.close();

    // Create and run the consumer
    Tool.run(std::make_unique<CallGraphGeneratorActionFactory>(GEI).get());
  }

  // Helper function to run the tool on multiple files
  void runToolOnMultipleFiles(const std::vector<std::string> &Codes,
                              const std::vector<std::string> &FileNames) {
    std::vector<std::string> Args = {"-std=c++17", "-fsyntax-only"};

    // Create a fixed compilation database
    std::string BuildDir = ".";
    auto Compilations =
        std::make_unique<FixedCompilationDatabase>(BuildDir, Args);

    // Create a clang tool
    ClangTool Tool(*Compilations, FileNames);

    // Write the codes to temporary files
    for (size_t i = 0; i < Codes.size(); ++i) {
      std::error_code EC;
      llvm::raw_fd_ostream OS(FileNames[i], EC, llvm::sys::fs::OF_None);
      if (EC) {
        llvm::errs() << "Error: " << EC.message() << "\n";
        continue;
      }
      OS << Codes[i];
      OS.close();
    }

    // Run the tool for each file individually
    for (size_t i = 0; i < FileNames.size(); ++i) {
      // Create a clang tool for just this file
      ClangTool Tool(*Compilations, {FileNames[i]});
      Tool.run(std::make_unique<CallGraphGeneratorActionFactory>(GEI).get());
    }
  }
};

// Test that function definitions are collected correctly
TEST_F(CallGraphGeneratorTest, CollectFunctionDefinitions) {
  const std::string Code = R"(
    void func1() {}
    void func2() {}
    int func3() { return 0; }
  )";

  runToolOnCode(Code, "test.cpp");

  // Check that we have 3 function definitions
  EXPECT_EQ(GEI.USRToFunctionMap.size(), 3u);

  // Check that we have the correct function names
  bool foundFunc1 = false;
  bool foundFunc2 = false;
  bool foundFunc3 = false;

  for (const auto &Entry : GEI.USRToFunctionMap) {
    if (Entry.second.FunctionName == "func1")
      foundFunc1 = true;
    if (Entry.second.FunctionName == "func2")
      foundFunc2 = true;
    if (Entry.second.FunctionName == "func3")
      foundFunc3 = true;
  }

  EXPECT_TRUE(foundFunc1);
  EXPECT_TRUE(foundFunc2);
  EXPECT_TRUE(foundFunc3);
}

// Test that function calls are collected correctly
TEST_F(CallGraphGeneratorTest, CollectFunctionCalls) {
  const std::string Code = R"(
    void func1() {}
    void func2() { func1(); }
    void func3() { func2(); }
  )";

  runToolOnCode(Code, "test.cpp");

  // Check that we have 3 function definitions
  EXPECT_EQ(GEI.USRToFunctionMap.size(), 3u);

  // Check that we have 2 function calls
  EXPECT_EQ(GEI.CallDependencies.size(), 2u);

  // Check that we have the correct call dependencies
  bool foundFunc2ToFunc1 = false;
  bool foundFunc3ToFunc2 = false;

  for (const auto &Call : GEI.CallDependencies) {
    auto CallerIt = GEI.USRToFunctionMap.find(Call.CallerUSR);
    auto CalleeIt = GEI.USRToFunctionMap.find(Call.CalleeUSR);

    if (CallerIt != GEI.USRToFunctionMap.end() &&
        CalleeIt != GEI.USRToFunctionMap.end()) {
      if (CallerIt->second.FunctionName == "func2" &&
          CalleeIt->second.FunctionName == "func1") {
        foundFunc2ToFunc1 = true;
      }
      if (CallerIt->second.FunctionName == "func3" &&
          CalleeIt->second.FunctionName == "func2") {
        foundFunc3ToFunc2 = true;
      }
    }
  }

  EXPECT_TRUE(foundFunc2ToFunc1);
  EXPECT_TRUE(foundFunc3ToFunc2);
}

// Test that cross-TU calls are collected correctly
TEST_F(CallGraphGeneratorTest, CollectCrossTUCalls) {
  const std::string Code1 = R"(
    void tu1Function() {}
  )";

  const std::string Code2 = R"(
    void tu1Function();  // Declaration
    void tu2Function() { tu1Function(); }  // Call to function in another TU
  )";

  runToolOnMultipleFiles({Code1, Code2}, {"tu1.cpp", "tu2.cpp"});

  // Check that we have 2 function definitions
  EXPECT_EQ(GEI.USRToFunctionMap.size(), 2u);

  // Check that we have 1 function call
  EXPECT_EQ(GEI.CallDependencies.size(), 1u);

  // Check that we have the correct call dependency
  bool foundTu2ToTu1 = false;

  for (const auto &Call : GEI.CallDependencies) {
    auto CallerIt = GEI.USRToFunctionMap.find(Call.CallerUSR);
    auto CalleeIt = GEI.USRToFunctionMap.find(Call.CalleeUSR);

    if (CallerIt != GEI.USRToFunctionMap.end() &&
        CalleeIt != GEI.USRToFunctionMap.end()) {
      if (CallerIt->second.FunctionName == "tu2Function" &&
          CalleeIt->second.FunctionName == "tu1Function") {
        foundTu2ToTu1 = true;

        // Check that they are defined in different TUs
        auto CalleeDefTU = GEI.USRToDefinedInTUMap.find(Call.CalleeUSR);
        EXPECT_NE(CallerIt->second.TU, CalleeDefTU->second);
      }
    }
  }

  EXPECT_TRUE(foundTu2ToTu1);
}

// Test that TU dependency graph is built correctly
TEST_F(CallGraphGeneratorTest, BuildTUDependencyGraph) {
  const std::string Code1 = R"(
    void tu1Function() {}
  )";

  const std::string Code2 = R"(
    void tu1Function();  // Declaration
    void tu2Function() { tu1Function(); }  // Call to function in another TU
  )";

  runToolOnMultipleFiles({Code1, Code2}, {"tu1.cpp", "tu2.cpp"});

  // Build the TU dependency graph
  auto TUDependencies = buildTUDependencyGraph(GEI);

  // Count the total number of dependencies
  size_t totalDependencies = 0;
  for (const auto &Entry : TUDependencies) {
    totalDependencies += Entry.second.size();
  }
  EXPECT_EQ(totalDependencies, 1u);
}

// Test that TU dependency graph is built correctly with manually populated data
TEST_F(CallGraphGeneratorTest, BuildTUDependencyGraphFromData) {
  // Create a new GlobalExceptionInfo object
  GlobalExceptionInfo TestGEI;

  // Define the TUs
  std::string TU1 = "/path/to/tu1.cpp";
  std::string TU2 = "/path/to/tu2.cpp";
  std::string TU3 = "/path/to/tu3.cpp";

  // Define the USRs
  std::string Func1USR = "c:@F@func1#";
  std::string Func2USR = "c:@F@func2#";
  std::string Func3USR = "c:@F@func3#";

  // Add function definitions to the USRToFunctionMap
  FunctionMappingInfo Func1Info;
  Func1Info.USR = Func1USR;
  Func1Info.TU = TU1;
  Func1Info.FunctionName = "func1";
  Func1Info.IsDefinition = true;
  TestGEI.USRToFunctionMap[Func1USR] = Func1Info;

  FunctionMappingInfo Func2Info;
  Func2Info.USR = Func2USR;
  Func2Info.TU = TU2;
  Func2Info.FunctionName = "func2";
  Func2Info.IsDefinition = true;
  TestGEI.USRToFunctionMap[Func2USR] = Func2Info;

  FunctionMappingInfo Func3Info;
  Func3Info.USR = Func3USR;
  Func3Info.TU = TU3;
  Func3Info.FunctionName = "func3";
  Func3Info.IsDefinition = true;
  TestGEI.USRToFunctionMap[Func3USR] = Func3Info;

  // Add function definitions to the USRToDefinedInTUMap
  TestGEI.USRToDefinedInTUMap[Func1USR] = TU1;
  TestGEI.USRToDefinedInTUMap[Func2USR] = TU2;
  TestGEI.USRToDefinedInTUMap[Func3USR] = TU3;

  // Add call dependencies
  CallDependency Call1;
  Call1.CallerUSR = Func2USR;
  Call1.CalleeUSR = Func1USR;
  TestGEI.CallDependencies.push_back(Call1);

  CallDependency Call2;
  Call2.CallerUSR = Func3USR;
  Call2.CalleeUSR = Func2USR;
  TestGEI.CallDependencies.push_back(Call2);

  // Build the TU dependency graph
  auto TUDependencies = buildTUDependencyGraph(TestGEI);

  // Count the total number of dependencies
  size_t totalDependencies = 0;
  for (const auto &Entry : TUDependencies) {
    totalDependencies += Entry.second.size();
  }
  EXPECT_EQ(totalDependencies, 2u);

  // Check that TU2 depends on TU1
  bool foundTu2ToTu1 = false;
  // Check that TU3 depends on TU2
  bool foundTu3ToTu2 = false;

  for (const auto &Entry : TUDependencies) {
    if (Entry.first == TU2) {
      for (const auto &Dependency : Entry.second) {
        if (Dependency == TU1) {
          foundTu2ToTu1 = true;
          break;
        }
      }
    } else if (Entry.first == TU3) {
      for (const auto &Dependency : Entry.second) {
        if (Dependency == TU2) {
          foundTu3ToTu2 = true;
          break;
        }
      }
    }
  }

  EXPECT_TRUE(foundTu2ToTu1);
  EXPECT_TRUE(foundTu3ToTu2);
}

// Test that TU dependency graph is built correctly for a more complex graph
TEST_F(CallGraphGeneratorTest, BuildComplexTUDependencyGraph) {
  const std::string Code1 = R"(
    void tu1Function() {}
  )";

  const std::string Code2 = R"(
    void tu1Function();  // Declaration
    void tu2Function() { tu1Function(); }  // Direct call to tu1Function
  )";

  const std::string Code3 = R"(
    void tu2Function();  // Declaration
    void tu3Function() { tu2Function(); }  // Direct call to tu2Function
  )";

  const std::string Code4 = R"(
    void tu1Function();  // Declaration
    void tu3Function();  // Declaration
    void tu4Function() { 
      tu1Function();  // Direct call to tu1Function
      tu3Function();  // Direct call to tu3Function
    }
  )";

  runToolOnMultipleFiles({Code1, Code2, Code3, Code4},
                         {"tu1.cpp", "tu2.cpp", "tu3.cpp", "tu4.cpp"});

  // Build the TU dependency graph
  auto TUDependencies = buildTUDependencyGraph(GEI);

  // Count the total number of dependencies
  size_t totalDependencies = 0;
  for (const auto &Entry : TUDependencies) {
    totalDependencies += Entry.second.size();
  }

  // We expect exactly 4 direct dependencies:
  // 1. tu2.cpp -> tu1.cpp (tu2Function calls tu1Function)
  // 2. tu3.cpp -> tu2.cpp (tu3Function calls tu2Function)
  // 3. tu4.cpp -> tu1.cpp (tu4Function calls tu1Function)
  // 4. tu4.cpp -> tu3.cpp (tu4Function calls tu3Function)
  EXPECT_EQ(totalDependencies, 4u);

  // Check that tu2.cpp depends on tu1.cpp (direct call)
  bool foundTu2ToTu1 = false;
  // Check that tu3.cpp depends on tu2.cpp (direct call)
  bool foundTu3ToTu2 = false;
  // Check that tu4.cpp depends on tu1.cpp and tu3.cpp (direct calls)
  bool foundTu4ToTu1 = false;
  bool foundTu4ToTu3 = false;

  for (const auto &Entry : TUDependencies) {
    if (Entry.first.find("tu2.cpp") != std::string::npos) {
      for (const auto &Dependency : Entry.second) {
        if (Dependency.find("tu1.cpp") != std::string::npos) {
          foundTu2ToTu1 = true;
        }
      }
    } else if (Entry.first.find("tu3.cpp") != std::string::npos) {
      for (const auto &Dependency : Entry.second) {
        if (Dependency.find("tu2.cpp") != std::string::npos) {
          foundTu3ToTu2 = true;
        }
      }
    } else if (Entry.first.find("tu4.cpp") != std::string::npos) {
      for (const auto &Dependency : Entry.second) {
        if (Dependency.find("tu1.cpp") != std::string::npos) {
          foundTu4ToTu1 = true;
        } else if (Dependency.find("tu3.cpp") != std::string::npos) {
          foundTu4ToTu3 = true;
        }
      }
    }
  }

  // Verify each direct dependency is found
  EXPECT_TRUE(foundTu2ToTu1) << "Missing direct dependency: tu2.cpp -> tu1.cpp";
  EXPECT_TRUE(foundTu3ToTu2) << "Missing direct dependency: tu3.cpp -> tu2.cpp";
  EXPECT_TRUE(foundTu4ToTu1) << "Missing direct dependency: tu4.cpp -> tu1.cpp";
  EXPECT_TRUE(foundTu4ToTu3) << "Missing direct dependency: tu4.cpp -> tu3.cpp";
}

// Test that TU cycles are detected correctly
TEST_F(CallGraphGeneratorTest, DetectTUCycles) {
  const std::string Code1 = R"(
    void tu2Function();  // Declaration
    void tu1Function() { tu2Function(); }  // Call to function in another TU
  )";

  const std::string Code2 = R"(
    void tu1Function();  // Declaration
    void tu2Function() { tu1Function(); }  // Call to function in another TU
  )";

  runToolOnMultipleFiles({Code1, Code2}, {"tu1.cpp", "tu2.cpp"});

  // Detect TU cycles
  auto Cycles = detectTUCycles(GEI);

  // Check that we have 1 cycle
  EXPECT_EQ(Cycles.size(), 1u);

  // Check that the cycle contains both TUs
  bool foundTu1 = false;
  bool foundTu2 = false;

  for (const auto &TU : Cycles[0]) {
    if (TU.find("tu1.cpp") != std::string::npos)
      foundTu1 = true;
    if (TU.find("tu2.cpp") != std::string::npos)
      foundTu2 = true;
  }

  EXPECT_TRUE(foundTu1);
  EXPECT_TRUE(foundTu2);
}

// Test that TU cycles are detected correctly with manually populated data
TEST_F(CallGraphGeneratorTest, DetectTUCyclesFromData) {
  // Create a new GlobalExceptionInfo object
  GlobalExceptionInfo TestGEI;

  // Define the TUs
  std::string TU1 = "/path/to/tu1.cpp";
  std::string TU2 = "/path/to/tu2.cpp";

  // Define the USRs
  std::string Func1USR = "c:@F@func1#";
  std::string Func2USR = "c:@F@func2#";

  // Add function definitions to the USRToFunctionMap
  FunctionMappingInfo Func1Info;
  Func1Info.USR = Func1USR;
  Func1Info.TU = TU1;
  Func1Info.FunctionName = "func1";
  Func1Info.IsDefinition = true;
  TestGEI.USRToFunctionMap[Func1USR] = Func1Info;

  FunctionMappingInfo Func2Info;
  Func2Info.USR = Func2USR;
  Func2Info.TU = TU2;
  Func2Info.FunctionName = "func2";
  Func2Info.IsDefinition = true;
  TestGEI.USRToFunctionMap[Func2USR] = Func2Info;

  // Add function definitions to the USRToDefinedInTUMap
  TestGEI.USRToDefinedInTUMap[Func1USR] = TU1;
  TestGEI.USRToDefinedInTUMap[Func2USR] = TU2;

  // Add call dependencies to create a cycle
  CallDependency Call1;
  Call1.CallerUSR = Func1USR;
  Call1.CalleeUSR = Func2USR;
  TestGEI.CallDependencies.push_back(Call1);

  CallDependency Call2;
  Call2.CallerUSR = Func2USR;
  Call2.CalleeUSR = Func1USR;
  TestGEI.CallDependencies.push_back(Call2);

  // Detect TU cycles
  auto Cycles = detectTUCycles(TestGEI);

  // Check that we have 1 cycle
  EXPECT_EQ(Cycles.size(), 1u);

  // Check that the cycle contains both TUs
  bool foundTu1 = false;
  bool foundTu2 = false;

  for (const auto &TU : Cycles[0]) {
    if (TU == TU1) {
      foundTu1 = true;
    } else if (TU == TU2) {
      foundTu2 = true;
    }
  }

  EXPECT_TRUE(foundTu1);
  EXPECT_TRUE(foundTu2);
}

// Test that constructor and destructor calls are collected correctly
TEST_F(CallGraphGeneratorTest, CollectConstructorCalls) {
  const std::string Code = R"(
    class MyClass {
    public:
      MyClass() {}
      ~MyClass() {}
    };
    void func() {
      MyClass obj;
    }
  )";

  runToolOnCode(Code, "test.cpp");

  // Check that we have the constructor and destructor definitions
  bool foundConstructor = false;
  bool foundDestructor = false;

  for (const auto &Entry : GEI.USRToFunctionMap) {
    if (Entry.second.FunctionName.find("MyClass") != std::string::npos) {
      if (Entry.second.FunctionName.find("~MyClass") != std::string::npos) {
        foundDestructor = true;
      } else {
        foundConstructor = true;
      }
    }
  }

  EXPECT_TRUE(foundConstructor);
  EXPECT_TRUE(foundDestructor);

  // Check that we have the constructor call
  bool foundConstructorCall = false;

  for (const auto &Call : GEI.CallDependencies) {
    auto CallerIt = GEI.USRToFunctionMap.find(Call.CallerUSR);
    auto CalleeIt = GEI.USRToFunctionMap.find(Call.CalleeUSR);

    if (CallerIt != GEI.USRToFunctionMap.end() &&
        CalleeIt != GEI.USRToFunctionMap.end()) {
      if (CallerIt->second.FunctionName == "func" &&
          CalleeIt->second.FunctionName.find("MyClass") != std::string::npos &&
          CalleeIt->second.FunctionName.find("~MyClass") == std::string::npos) {
        foundConstructorCall = true;
      }
    }
  }

  EXPECT_TRUE(foundConstructorCall);
}

// Test that operator new and delete calls are collected correctly
TEST_F(CallGraphGeneratorTest, CollectOperatorNewDelete) {
  const std::string Code = R"(
    class MyClass {
    public:
      void* operator new(size_t size) { return ::operator new(size); }
      void operator delete(void* ptr) { ::operator delete(ptr); }
    };
    void func() {
      MyClass* obj = new MyClass();
      delete obj;
    }
  )";

  runToolOnCode(Code, "test.cpp");

  // Check that we have the operator new and delete definitions
  bool foundOperatorNew = false;
  bool foundOperatorDelete = false;

  for (const auto &Entry : GEI.USRToFunctionMap) {
    if (Entry.second.FunctionName.find("operator new") != std::string::npos) {
      foundOperatorNew = true;
    }
    if (Entry.second.FunctionName.find("operator delete") !=
        std::string::npos) {
      foundOperatorDelete = true;
    }
  }

  EXPECT_TRUE(foundOperatorNew);
  EXPECT_TRUE(foundOperatorDelete);

  // Check that we have the operator new and delete calls
  bool foundOperatorNewCall = false;
  bool foundOperatorDeleteCall = false;

  for (const auto &Call : GEI.CallDependencies) {
    auto CallerIt = GEI.USRToFunctionMap.find(Call.CallerUSR);
    auto CalleeIt = GEI.USRToFunctionMap.find(Call.CalleeUSR);

    if (CallerIt != GEI.USRToFunctionMap.end() &&
        CalleeIt != GEI.USRToFunctionMap.end()) {
      if (CallerIt->second.FunctionName == "func") {
        if (CalleeIt->second.FunctionName.find("operator new") !=
            std::string::npos) {
          foundOperatorNewCall = true;
        }
        if (CalleeIt->second.FunctionName.find("operator delete") !=
            std::string::npos) {
          foundOperatorDeleteCall = true;
        }
      }
    }
  }

  EXPECT_TRUE(foundOperatorNewCall);
  EXPECT_TRUE(foundOperatorDeleteCall);
}

// Test that DOT file generation works correctly
TEST_F(CallGraphGeneratorTest, GenerateDependencyDotFile) {
  const std::string Code1 = R"(
    void tu1Function() {}
  )";

  const std::string Code2 = R"(
    void tu1Function();  // Declaration
    void tu2Function() { tu1Function(); }  // Call to function in another TU
  )";

  runToolOnMultipleFiles({Code1, Code2}, {"tu1.cpp", "tu2.cpp"});

  // Generate DOT file
  std::string OutputPath = "dependencies.dot";
  generateDependencyDotFile(GEI, OutputPath);

  // Read and verify DOT file content
  std::ifstream DotFile(OutputPath);
  ASSERT_TRUE(DotFile.is_open()) << "Failed to open DOT file: " << OutputPath;

  std::string Content((std::istreambuf_iterator<char>(DotFile)),
                      std::istreambuf_iterator<char>());
  DotFile.close();

  // Check for expected DOT syntax
  EXPECT_TRUE(Content.find("digraph TUDependencies") != std::string::npos);
  EXPECT_TRUE(Content.find("rankdir=LR") != std::string::npos);
  EXPECT_TRUE(Content.find("node [shape=box") != std::string::npos);

  // Check for expected nodes
  EXPECT_TRUE(Content.find("tu1.cpp") != std::string::npos);
  EXPECT_TRUE(Content.find("tu2.cpp") != std::string::npos);

  // Check for expected edge
  EXPECT_TRUE(Content.find("tu2.cpp") != std::string::npos &&
              Content.find("tu1.cpp") != std::string::npos &&
              Content.find("->") != std::string::npos);

  // Clean up
  std::remove(OutputPath.c_str());
}

// Test that template function calls are collected correctly
TEST_F(CallGraphGeneratorTest, CollectTemplateFunctionCalls) {
  const std::string Code = R"(
    template<typename T>
    void templateFunc(T value) {}
    
    void func() {
      templateFunc<int>(42);
      templateFunc<double>(3.14);
    }
  )";

  runToolOnCode(Code, "test.cpp");

  // Check that we have the template function definition
  bool foundTemplateFunc = false;

  for (const auto &Entry : GEI.USRToFunctionMap) {
    if (Entry.second.FunctionName.find("templateFunc") != std::string::npos) {
      foundTemplateFunc = true;
      break;
    }
  }

  EXPECT_TRUE(foundTemplateFunc);

  // Check that we have the template function calls
  int templateCallCount = 0;

  for (const auto &Call : GEI.CallDependencies) {
    auto CallerIt = GEI.USRToFunctionMap.find(Call.CallerUSR);
    auto CalleeIt = GEI.USRToFunctionMap.find(Call.CalleeUSR);

    if (CallerIt != GEI.USRToFunctionMap.end() &&
        CalleeIt != GEI.USRToFunctionMap.end()) {
      if (CallerIt->second.FunctionName == "func" &&
          CalleeIt->second.FunctionName.find("templateFunc") !=
              std::string::npos) {
        templateCallCount++;
      }
    }
  }

  // We expect two calls to the template function
  EXPECT_EQ(templateCallCount, 2);
}

// Test handling of undefined functions
TEST_F(CallGraphGeneratorTest, HandleUndefinedFunctions) {
  const std::string Code = R"(
    void func1();  // Declaration only
    void func2() { func1(); }  // Call to undefined function
  )";

  runToolOnCode(Code, "test.cpp");

  // Check that we have the function declaration
  bool foundFunc1Decl =
      llvm::find_if(GEI.USRToFunctionMap, [](const auto &Entry) {
        return Entry.second.FunctionName == "func1";
      }) == GEI.USRToFunctionMap.end();

  EXPECT_FALSE(foundFunc1Decl);

  // Check that we have the function call
  bool foundFuncCall = false;

  for (const auto &Call : GEI.CallDependencies) {
    auto CallerIt = GEI.USRToFunctionMap.find(Call.CallerUSR);
    auto CalleeIt = GEI.USRToFunctionMap.find(Call.CalleeUSR);

    if (CallerIt != GEI.USRToFunctionMap.end() &&
        CalleeIt != GEI.USRToFunctionMap.end()) {
      if (CallerIt->second.FunctionName == "func2" &&
          CalleeIt->second.FunctionName == "func1") {
        foundFuncCall = true;
        break;
      }
    }
  }

  EXPECT_TRUE(foundFuncCall);
}

// Test handling of lambda expressions
TEST_F(CallGraphGeneratorTest, HandleLambdaExpressions) {
  const std::string Code = R"(
    void func() {
      auto lambda = []() { return 42; };
      lambda();
    }
  )";

  runToolOnCode(Code, "test.cpp");

  // Check that we have the lambda call
  bool foundLambdaCall = false;

  for (const auto &Call : GEI.CallDependencies) {
    auto CallerIt = GEI.USRToFunctionMap.find(Call.CallerUSR);
    auto CalleeIt = GEI.USRToFunctionMap.find(Call.CalleeUSR);

    if (CallerIt != GEI.USRToFunctionMap.end() &&
        CalleeIt != GEI.USRToFunctionMap.end()) {
      if (CallerIt->second.FunctionName == "func") {
        // Lambda functions have special names in Clang
        if (CalleeIt->second.FunctionName.find("operator()") !=
            std::string::npos) {
          foundLambdaCall = true;
          break;
        }
      }
    }
  }

  EXPECT_TRUE(foundLambdaCall);
}

// Test that direct TU dependencies are collected correctly
TEST_F(CallGraphGeneratorTest, BuildDirectTUDependencyGraph) {
  const std::string Code1 = R"(
    void tu1Function() {}
  )";

  const std::string Code2 = R"(
    void tu1Function();  // Declaration
    void tu2Function() { tu1Function(); }  // Direct call to tu1
  )";

  const std::string Code3 = R"(
    void tu2Function();  // Declaration
    void tu3Function() { tu2Function(); }  // Direct call to tu2
  )";

  runToolOnMultipleFiles({Code1, Code2, Code3},
                         {"tu1.cpp", "tu2.cpp", "tu3.cpp"});

  // Build the TU dependency graph
  auto TUDependencies = buildTUDependencyGraph(GEI);

  // Count the total number of dependencies
  size_t totalDependencies = 0;
  for (const auto &Entry : TUDependencies) {
    totalDependencies += Entry.second.size();
  }

  // We expect exactly 2 direct dependencies:
  // 1. tu2.cpp -> tu1.cpp (tu2Function calls tu1Function)
  // 2. tu3.cpp -> tu2.cpp (tu3Function calls tu2Function)
  EXPECT_EQ(totalDependencies, 2u);

  // Check that tu2.cpp depends on tu1.cpp (direct call)
  bool foundTu2ToTu1 = false;
  // Check that tu3.cpp depends on tu2.cpp (direct call)
  bool foundTu3ToTu2 = false;

  for (const auto &Entry : TUDependencies) {
    if (Entry.first.find("tu2.cpp") != std::string::npos) {
      for (const auto &Dependency : Entry.second) {
        if (Dependency.find("tu1.cpp") != std::string::npos) {
          foundTu2ToTu1 = true;
        }
      }
    } else if (Entry.first.find("tu3.cpp") != std::string::npos) {
      for (const auto &Dependency : Entry.second) {
        if (Dependency.find("tu2.cpp") != std::string::npos) {
          foundTu3ToTu2 = true;
        }
      }
    }
  }

  // Verify each direct dependency is found
  EXPECT_TRUE(foundTu2ToTu1) << "Missing direct dependency: tu2.cpp -> tu1.cpp";
  EXPECT_TRUE(foundTu3ToTu2) << "Missing direct dependency: tu3.cpp -> tu2.cpp";
}

// Test that transitive TU dependencies are collected correctly
TEST_F(CallGraphGeneratorTest, BuildTransitiveTUDependencyGraph) {
  const std::string Code1 = R"(
    void tu1Function() {}
  )";

  const std::string Code2 = R"(
    void tu1Function();  // Declaration
    void tu2Function() { tu1Function(); }  // Direct call to tu1
  )";

  const std::string Code3 = R"(
    void tu2Function();  // Declaration
    void tu3Function() { tu2Function(); }  // Direct call to tu2
  )";

  runToolOnMultipleFiles({Code1, Code2, Code3},
                         {"tu1.cpp", "tu2.cpp", "tu3.cpp"});

  // Build the TU dependency graph with transitive dependencies
  auto TUDependencies = buildTUDependencyGraph(GEI);
  computeTransitiveClosure(TUDependencies);

  // Count the total number of dependencies
  size_t totalDependencies = 0;
  for (const auto &Entry : TUDependencies) {
    totalDependencies += Entry.second.size();
  }

  // We expect 3 dependencies after transitive closure:
  // 1. tu2.cpp -> tu1.cpp (direct)
  // 2. tu3.cpp -> tu2.cpp (direct)
  // 3. tu3.cpp -> tu1.cpp (transitive through tu2)
  EXPECT_EQ(totalDependencies, 3u);

  // Check that tu2.cpp depends on tu1.cpp (direct)
  bool foundTu2ToTu1 = false;
  // Check that tu3.cpp depends on tu2.cpp (direct)
  bool foundTu3ToTu2 = false;
  // Check that tu3.cpp depends on tu1.cpp (transitive)
  bool foundTu3ToTu1 = false;

  for (const auto &Entry : TUDependencies) {
    if (Entry.first.find("tu2.cpp") != std::string::npos) {
      for (const auto &Dependency : Entry.second) {
        if (Dependency.find("tu1.cpp") != std::string::npos) {
          foundTu2ToTu1 = true;
        }
      }
    } else if (Entry.first.find("tu3.cpp") != std::string::npos) {
      for (const auto &Dependency : Entry.second) {
        if (Dependency.find("tu2.cpp") != std::string::npos) {
          foundTu3ToTu2 = true;
        } else if (Dependency.find("tu1.cpp") != std::string::npos) {
          foundTu3ToTu1 = true;
        }
      }
    }
  }

  // Verify direct dependencies are found
  EXPECT_TRUE(foundTu2ToTu1) << "Missing direct dependency: tu2.cpp -> tu1.cpp";
  EXPECT_TRUE(foundTu3ToTu2) << "Missing direct dependency: tu3.cpp -> tu2.cpp";
  // Verify transitive dependency is found
  EXPECT_TRUE(foundTu3ToTu1)
      << "Missing transitive dependency: tu3.cpp -> tu1.cpp";
}

} // namespace