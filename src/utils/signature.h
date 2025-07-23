#pragma once

// signature.h – tiny 64-bit pattern scanner utilities
//   find_u64(const uint8_t* data, size_t len, uint64_t value) -> optional<size_t>
//   find_absolute(...) – preset to legacy sentinel 0x123456789ABCDEF

#include <cstdint>
#include <optional>
#include <vector>

namespace utils::sig {

constexpr uint64_t k_absolute_sentinel = 0x123456789ABCDEFULL;
constexpr size_t   k_qword = sizeof(uint64_t);
using byte_t = uint8_t;

[[nodiscard]] inline std::optional<size_t>
find_u64(const byte_t* data, size_t len, uint64_t value) noexcept {
  if (len < k_qword) return std::nullopt;
  len -= k_qword;
  for (size_t i = 0; i <= len; ++i) {
    if (*reinterpret_cast<const uint64_t*>(data + i) == value) return i;
  }
  return std::nullopt;
}

[[nodiscard]] inline std::optional<size_t>
find_u64(const std::vector<byte_t>& v, uint64_t val) noexcept {
  return find_u64(v.data(), v.size(), val);
}

[[nodiscard]] inline std::optional<size_t>
find_absolute(const byte_t* data, size_t len) noexcept {
  return find_u64(data, len, k_absolute_sentinel);
}

[[nodiscard]] inline std::optional<size_t>
find_absolute(const std::vector<byte_t>& v) noexcept {
  return find_u64(v.data(), v.size(), k_absolute_sentinel);
}

} // namespace utils::sig 