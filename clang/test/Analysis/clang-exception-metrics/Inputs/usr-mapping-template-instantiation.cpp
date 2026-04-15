// Test: USR mapping must register implicit template instantiations.
// Before fix: vector<int>::push_back(int&&) USR was missing from
// USRToFunctionMap, causing "USR not found" errors in reporting.
// After fix: shouldVisitTemplateInstantiations() = true ensures
// all instantiated methods are registered.

#include <vector>

void calls_push_back_rvalue() {
    std::vector<int> v;
    v.push_back(42);
}
