#pragma once

#include <cstdarg>
#include <cstdio>

namespace utils::log {

inline void vprint(FILE* stream, const char* fmt, va_list ap) noexcept {
  std::vfprintf(stream, fmt, ap);
  std::fflush(stream);
}

inline void errorf(const char* fmt, ...) noexcept {
  va_list ap;
  va_start(ap, fmt);
  vprint(stderr, fmt, ap);
  va_end(ap);
}

inline void warnf(const char* fmt, ...) noexcept {
  va_list ap;
  va_start(ap, fmt);
  vprint(stderr, fmt, ap);
  va_end(ap);
}

inline void infof(const char* fmt, ...) noexcept {
  va_list ap;
  va_start(ap, fmt);
  vprint(stdout, fmt, ap);
  va_end(ap);
}

}  // namespace utils::log 