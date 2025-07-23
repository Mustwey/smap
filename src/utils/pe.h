#pragma once

// pe.h – small PE-image helper functions (header-only, no extras)
//  * IsExecutablePage(DWORD prot)
//  * IsExecutableSection(const IMAGE_SECTION_HEADER&)
//  * SectionName(const IMAGE_SECTION_HEADER&)
//  * NameContains(const IMAGE_SECTION_HEADER&, const char*)
//  * IsInvalidAlignmentSection(const IMAGE_SECTION_HEADER&)

#include <Windows.h>
#include <cstring>
#include <string_view>
#include <array>

namespace utils::pe {

constexpr size_t kPeNameLen = IMAGE_SIZEOF_SHORT_NAME;
constexpr std::array<const char*, 1> kInvalidNames = {"text"};

// Returns true if protection flags indicate executable memory.
[[nodiscard]] inline constexpr bool IsExecutablePage(DWORD prot) noexcept {
  return prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ ||
         prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
}

// Returns true if section header characteristics indicate executable memory.
[[nodiscard]] inline constexpr bool IsExecutableSection(
    const IMAGE_SECTION_HEADER& sec) noexcept {
  return (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}

// Returns the PE section name as a std::string_view.
[[nodiscard]] inline std::string_view SectionName(
    const IMAGE_SECTION_HEADER& sec) noexcept {
  size_t len = strnlen(reinterpret_cast<const char*>(sec.Name), kPeNameLen);
  return std::string_view(reinterpret_cast<const char*>(sec.Name), len);
}

// Case-insensitive substring match on section name.
[[nodiscard]] inline bool NameContains(
    const IMAGE_SECTION_HEADER& sec, const char* needle) noexcept {
  std::string_view name = SectionName(sec);
  const size_t needle_len = strlen(needle);
  if (needle_len > name.size()) return false;
  for (size_t i = 0; i + needle_len <= name.size(); ++i) {
    if (_strnicmp(name.data() + i, needle, needle_len) == 0) return true;
  }
  return false;
}

// Identifies sections that are either non-executable or match banned names.
[[nodiscard]] inline bool IsInvalidAlignmentSection(
    const IMAGE_SECTION_HEADER& sec) noexcept {
  if (!IsExecutableSection(sec)) return true;
  for (const char* banned : kInvalidNames)
    if (NameContains(sec, banned)) return true;
  return false;
}

}  // namespace utils::pe
h