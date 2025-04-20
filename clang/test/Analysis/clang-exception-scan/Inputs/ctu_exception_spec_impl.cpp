#include "stdexcept.h"

void safe_function() {
    // Does nothing, can be noexcept
}

void throwing_function() {
    throw std::runtime_error("error");
} 