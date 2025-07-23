#pragma once

// pe.h – PE “utility” helpers (header-only, no heavy extras)
//
//  * IsExecutablePage(DWORD prot)
//  * IsExecutableSection(const IMAGE_SECTION_HEADER&)
//  * SectionName(const IMAGE_SECTION_HEADER&)
//  * NameContains(const IMAGE_SECTION_HEADER&, const char*)
//  * IsInvalidAlignmentSection(const IMAGE_SECTION_HEADER&)
//  * FindImportEntry(HANDLE proc, std::wstring_view module,
//                    std::string_view import)

#include <Windows.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>

#include "utils/process.h"

namespace utils::pe {

using byte_t = std::uint8_t;

constexpr std::size_t kPeNameLen = IMAGE_SIZEOF_SHORT_NAME;
constexpr std::array<const char*, 1> kInvalidNames = {"text"};

// ---------------------------------------------------------------------------
//  Small helpers
// ---------------------------------------------------------------------------
[[nodiscard]] inline constexpr bool IsExecutablePage(DWORD prot) noexcept {
  return prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ ||
         prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
}

[[nodiscard]] inline constexpr bool IsExecutableSection(
    const IMAGE_SECTION_HEADER& s) noexcept {
  return (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}

[[nodiscard]] inline std::string_view SectionName(
    const IMAGE_SECTION_HEADER& s) noexcept {
  const auto len = strnlen(reinterpret_cast<const char*>(s.Name), kPeNameLen);
  return {reinterpret_cast<const char*>(s.Name), len};
}

[[nodiscard]] inline bool NameContains(
    const IMAGE_SECTION_HEADER& s, const char* needle) noexcept {
  const std::string_view name = SectionName(s);
  const std::size_t nlen = std::strlen(needle);
  if (nlen > name.size()) return false;

  for (std::size_t i = 0; i + nlen <= name.size(); ++i)
    if (_strnicmp(name.data() + i, needle, nlen) == 0) return true;

  return false;
}

[[nodiscard]] inline bool IsInvalidAlignmentSection(
    const IMAGE_SECTION_HEADER& s) noexcept {
  if (!IsExecutableSection(s)) return true;
  for (const auto* banned : kInvalidNames)
    if (NameContains(s, banned)) return true;
  return false;
}

// ---------------------------------------------------------------------------
//  Import-table helper
// ---------------------------------------------------------------------------
[[nodiscard]] inline std::optional<PBYTE> FindImportEntry(
    HANDLE proc, std::wstring_view module, std::string_view import) noexcept {
  auto mod = utils::process::get_module(proc, module);
  if (!mod) return std::nullopt;

  IMAGE_DOS_HEADER dos{};
  if (!ReadProcessMemory(proc, mod->modBaseAddr, &dos, sizeof dos, nullptr) ||
      dos.e_magic != IMAGE_DOS_SIGNATURE)
    return std::nullopt;

  IMAGE_NT_HEADERS nt{};
  const auto* nt_ptr =
      reinterpret_cast<const byte_t*>(mod->modBaseAddr) + dos.e_lfanew;
  if (!ReadProcessMemory(proc, nt_ptr, &nt, sizeof nt, nullptr) ||
      nt.Signature != IMAGE_NT_SIGNATURE)
    return std::nullopt;

  DWORD rva =
      nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  if (!rva) return std::nullopt;

  for (;; rva += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
    IMAGE_IMPORT_DESCRIPTOR desc{};
    if (!ReadProcessMemory(proc,
                           reinterpret_cast<const byte_t*>(mod->modBaseAddr) +
                               rva,
                           &desc, sizeof desc, nullptr))
      break;
    if (!desc.OriginalFirstThunk) break;

    DWORD thunk = desc.OriginalFirstThunk;
    for (DWORD idx = 0;; ++idx, thunk += sizeof(IMAGE_THUNK_DATA)) {
      IMAGE_THUNK_DATA itd{};
      if (!ReadProcessMemory(proc,
                             reinterpret_cast<const byte_t*>(mod->modBaseAddr) +
                                 thunk,
                             &itd, sizeof itd, nullptr) ||
          !itd.u1.AddressOfData)
        break;

      char name[256]{};
      ReadProcessMemory(proc,
                        reinterpret_cast<const byte_t*>(mod->modBaseAddr) +
                            itd.u1.AddressOfData +
                            offsetof(IMAGE_IMPORT_BY_NAME, Name),
                        name, sizeof name, nullptr);

      if (_stricmp(name, import.data()) == 0) {
        return reinterpret_cast<PBYTE>(mod->modBaseAddr) + desc.FirstThunk +
               idx * sizeof(PVOID);
      }
    }
  }

  return std::nullopt;
}

}  // namespace utils::pe
