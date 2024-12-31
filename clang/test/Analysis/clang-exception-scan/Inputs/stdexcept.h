#ifndef _STDEXCEPT_
#define _STDEXCEPT_

#include "exception"

namespace std {
class runtime_error {
public:
  runtime_error(const char *);
};

class logic_error {
public:
  logic_error(const char *);
};
} // namespace std

#endif