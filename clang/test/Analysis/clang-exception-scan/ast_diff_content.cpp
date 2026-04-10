// Test that --ast-diff detects meaningful AST differences when noexcept is
// applied to a function referenced in noexcept(expr) and template
// instantiations. Uses in-memory VFS overlay — no files written to disk.
//
// RUN: %gen_compdb %s > %t.json
// RUN: rm -rf %t.output
// RUN: mkdir -p %t.output
// RUN: %clang_exception_scan --ast-diff %t.json %t.output
//
// Verify the AST diff output contains the meaningful template change.
// RUN: cat %t.output/ast_diff.txt | FileCheck %s --check-prefix=CHECK-DIFF

// helper is safe — definite match. When it gains noexcept, the template
// instantiation of invoke changes from void(*)() to void(*)() noexcept.
void helper() {}

template<typename F>
void invoke(F f) noexcept(noexcept(f())) {
  f();
}

void use_invoke() {
  invoke(helper);
}

// The AST diff should show the template argument type changed.
// CHECK-DIFF: TemplateArgument type 'void (*)() noexcept'
// CHECK-DIFF: FunctionProtoType {{.*}} 'void () noexcept' exceptionspec_basic_noexcept
