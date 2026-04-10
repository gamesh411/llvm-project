// Implementation file for ctu_apply_noexcept.cpp test.
#include "stdexcept.h"

void cross_tu_safe() {}

void cross_tu_throwing() {
  throw std::runtime_error("error");
}
