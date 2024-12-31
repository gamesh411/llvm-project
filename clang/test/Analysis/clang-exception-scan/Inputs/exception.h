#ifndef _EXCEPTION_
#define _EXCEPTION_

namespace std {
class exception {
public:
  virtual ~exception() noexcept;
};

class bad_exception : public exception {
public:
  bad_exception() noexcept;
};
} // namespace std

#endif