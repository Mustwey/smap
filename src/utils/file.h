#pragma once

#include <fstream>
#include <optional>
#include <string_view>
#include <vector>
#include <cstdint>

namespace utils::io {

// Reads an entire file into a `std::vector<std::uint8_t>`.
// Returns std::nullopt on any failure.
[[nodiscard]] inline std::optional<std::vector<std::uint8_t>>
ReadFile(std::wstring_view path) noexcept {
  std::ifstream f(path.data(), std::ios::binary | std::ios::ate);
  if (!f) return std::nullopt;

  const std::streamsize size = f.tellg();
  if (size <= 0) return std::nullopt;

  f.seekg(0, std::ios::beg);
  std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
  if (!f.read(reinterpret_cast<char*>(data.data()), size)) return std::nullopt;

  return data;
}

}  // namespace utils::io 