#ifndef LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_SERIALIZATION_H
#define LLVM_CLANG_TOOLS_CLANG_EXCEPTION_SCAN_SERIALIZATION_H

#include "ExceptionAnalyzer.h"
#include "llvm/Support/YAMLTraits.h"

namespace ES = clang::exception_scan;

template <> struct llvm::yaml::ScalarEnumerationTraits<ES::ExceptionState> {
  static void enumeration(llvm::yaml::IO &IO, ES::ExceptionState &ES) {
    IO.enumCase(ES, "Throwing", ES::ExceptionState::Throwing);
    IO.enumCase(ES, "NotThrowing", ES::ExceptionState::NotThrowing);
    IO.enumCase(ES, "Unknown", ES::ExceptionState::Unknown);
  }
};

template <>
struct llvm::yaml::ScalarEnumerationTraits<clang::ExceptionSpecificationType> {
  static void enumeration(llvm::yaml::IO &IO,
                          clang::ExceptionSpecificationType &ES) {
    IO.enumCase(ES, "None", clang::EST_None);
    IO.enumCase(ES, "DynamicNone", clang::EST_DynamicNone);
    IO.enumCase(ES, "Dynamic", clang::EST_Dynamic);
    IO.enumCase(ES, "MSAny", clang::EST_MSAny);
    IO.enumCase(ES, "NoThrow", clang::EST_NoThrow);
    IO.enumCase(ES, "BasicNoexcept", clang::EST_BasicNoexcept);
    IO.enumCase(ES, "DependentNoexcept", clang::EST_DependentNoexcept);
    IO.enumCase(ES, "NoexceptFalse", clang::EST_NoexceptFalse);
    IO.enumCase(ES, "NoexceptTrue", clang::EST_NoexceptTrue);
    IO.enumCase(ES, "Unevaluated", clang::EST_Unevaluated);
    IO.enumCase(ES, "Uninstantiated", clang::EST_Uninstantiated);
    IO.enumCase(ES, "Unparsed", clang::EST_Unparsed);
  }
};

template <> struct llvm::yaml::MappingTraits<ES::PerFunctionExceptionInfo> {
  static void mapping(llvm::yaml::IO &IO, ES::PerFunctionExceptionInfo &EC) {
    IO.mapRequired("FirstDeclaredInFile", EC.FirstDeclaredInFile);
    IO.mapRequired("DefinedInFile", EC.DefinedInFile);
    IO.mapRequired("FunctionName", EC.FunctionName);
    IO.mapRequired("FunctionUSRName", EC.FunctionUSRName);
    IO.mapRequired("Behaviour", EC.Behaviour);
    IO.mapRequired("ContainsUnknown", EC.ContainsUnknown);
    IO.mapRequired("ExceptionTypeList", EC.ExceptionTypeList);
    IO.mapRequired("ExceptionSpecification", EC.ExceptionSpecification);
    IO.mapRequired("IsInMainFile", EC.IsInMainFile);
  }
};

template <> struct llvm::yaml::SequenceTraits<ES::ExceptionContext> {
  static size_t size(llvm::yaml::IO &IO, ES::ExceptionContext &EC) {
    return EC.InfoPerFunction.size();
  }
  static ES::PerFunctionExceptionInfo &
  element(llvm::yaml::IO &IO, ES::ExceptionContext &EC, size_t Index) {
    return EC.InfoPerFunction[Index];
  }
};

#endif
