#pragma once

class ExceptionInfo;

namespace clang {
class SourceManager;
} // namespace clang

class ExceptionInfoConsumer {
public:
  ExceptionInfoConsumer(ExceptionInfo &EI, clang::SourceManager &SM)
      : EI(EI), SM(SM) {}

protected:
  ExceptionInfo &EI;
  clang::SourceManager &SM;
};
