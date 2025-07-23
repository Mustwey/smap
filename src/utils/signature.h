#pragma once

// signature.h – small pattern scanning helpers
//   find_u64(span)        -> search for a 64-bit value
//   find_absolute(span)   -> search for legacy sentinel 0x123456789ABCDEF

#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <vector>
#include <type_traits>

namespace utils::sig {

using byte_t = std::uint8_t;
constexpr std::uint64_t kAbsoluteSentinel = 0x123456789ABCDEFULL;

namespace detail {

// Generic contiguous pattern finder.
template <typename T>
[[nodiscard]] inline std::optional<size_t>
find_value(std::span<const byte_t> data, const T& value) noexcept {
  static_assert(std::is_trivially_copyable_v<T>);
  const auto* val_bytes = reinterpret_cast<const byte_t*>(&value);
  const size_t val_size = sizeof(T);

  if (data.size() < val_size) return std::nullopt;

  for (size_t i = 0; i <= data.size() - val_size; ++i) {
    if (std::memcmp(data.data() + i, val_bytes, val_size) == 0) return i;
  }
  return std::nullopt;
}

}  // namespace detail

// Typed overloads for different sources.
[[nodiscard]] inline std::optional<size_t>
find_u64(std::span<const byte_t> data, std::uint64_t value) noexcept {
  return detail::find_value(data, value);
}

[[nodiscard]] inline std::optional<size_t>
find_u64(const byte_t* data, size_t len, std::uint64_t value) noexcept {
  return find_u64(std::span{data, len}, value);
}

[[nodiscard]] inline std::optional<size_t>
find_u64(const std::vector<byte_t>& vec, std::uint64_t value) noexcept {
  return find_u64(std::span{vec.data(), vec.size()}, value);
}

// Absolute address sentinel scanning.
[[nodiscard]] inline std::optional<size_t>
find_absolute(std::span<const byte_t> data) noexcept {
  return find_u64(data, kAbsoluteSentinel);
}

[[nodiscard]] inline std::optional<size_t>
find_absolute(const byte_t* data, size_t len) noexcept {
  return find_u64(std::span{data, len}, kAbsoluteSentinel);
}

[[nodiscard]] inline std::optional<size_t>
find_absolute(const std::vector<byte_t>& vec) noexcept {
  return find_u64(std::span{vec.data(), vec.size()}, kAbsoluteSentinel);
}

}  // namespace utils::sig