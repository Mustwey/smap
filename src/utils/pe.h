#pragma once

// pe.h – small PE-image helper functions (header-only, no extras)
//  * is_executable_page(DWORD prot)
//  * is_invalid_alignment_section(const IMAGE_SECTION_HEADER&)
//    (true when section is non-exec or its name contains "text")

#include <Windows.h>
#include <cstring>

namespace utils::pe {

// True if the protection flags indicate executable memory.
[[nodiscard]] inline constexpr bool is_executable_page(DWORD prot) noexcept {
  return prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ ||
         prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
}

constexpr size_t k_pe_name_len = 8;

// Case-insensitive ASCII substring search (max 8-byte PE section name).
[[nodiscard]] inline bool name_contains(const IMAGE_SECTION_HEADER& sec,
                                        const char* needle) noexcept {
  char name[k_pe_name_len + 1]{};
  memcpy(name, sec.Name, k_pe_name_len);
  const size_t n_len = strlen(needle);
  for (size_t i = 0; i + n_len <= k_pe_name_len && name[i]; ++i) {
    if (_strnicmp(&name[i], needle, n_len) == 0) return true;
  }
  return false;
}

[[nodiscard]] inline bool
is_invalid_alignment_section(const IMAGE_SECTION_HEADER& sec) noexcept {
  constexpr const char* k_text = "text";
  return !(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
         name_contains(sec, k_text);
}

} // namespace utils::pe 