#pragma once

// process.h – tiny helpers around Win32 Toolhelp API (no wrappers, no RAII).
// Provides:
//   get_process(const wchar_t* name)                -> optional<PROCESSENTRY32>
//   get_module (HANDLE proc, const wchar_t* name)   -> optional<MODULEENTRY32>
//   list_modules(HANDLE proc)                       -> vector<ModuleInfo>
// A ModuleInfo contains MODULEENTRY32 and its section headers.

#include <Windows.h>
#include <TlHelp32.h>

#include <optional>
#include <vector>

namespace utils::process {

constexpr DWORD k_snap_modules = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;

using byte_t = unsigned char;
// -------------------------- helpers ----------------------------------------
[[nodiscard]] inline bool iequals(const wchar_t* a, const wchar_t* b) noexcept {
  return _wcsicmp(a, b) == 0;
}

// -------------------------- core API ---------------------------------------
[[nodiscard]] inline std::optional<PROCESSENTRY32>
get_process(const wchar_t* exe) noexcept {
  const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return std::nullopt;

  PROCESSENTRY32 e{sizeof(e)};
  if (Process32First(snap, &e)) {
    do {
      if (iequals(e.szExeFile, exe)) {
        CloseHandle(snap);
        return e;
      }
    } while (Process32Next(snap, &e));
  }
  CloseHandle(snap);
  return std::nullopt;
}

[[nodiscard]] inline std::optional<MODULEENTRY32>
get_module(HANDLE proc, const wchar_t* name) noexcept {
  const DWORD pid = GetProcessId(proc);
  const HANDLE snap = CreateToolhelp32Snapshot(k_snap_modules, pid);
  if (snap == INVALID_HANDLE_VALUE) return std::nullopt;

  MODULEENTRY32 m{sizeof(m)};
  if (Module32First(snap, &m)) {
    do {
      if (iequals(m.szModule, name)) {
        CloseHandle(snap);
        return m;
      }
    } while (Module32Next(snap, &m));
  }
  CloseHandle(snap);
  return std::nullopt;
}

struct ModuleInfo {
  MODULEENTRY32 mod;
  std::vector<IMAGE_SECTION_HEADER> sections;
};

[[nodiscard]] inline std::vector<IMAGE_SECTION_HEADER>
read_sections(HANDLE proc, const MODULEENTRY32& mod) noexcept {
  std::vector<IMAGE_SECTION_HEADER> out;
  IMAGE_DOS_HEADER dos{};
  if (!ReadProcessMemory(proc, mod.modBaseAddr, &dos, sizeof dos, nullptr) ||
      dos.e_magic != IMAGE_DOS_SIGNATURE)
    return out;

  IMAGE_NT_HEADERS nt{};
  const byte_t* nt_ptr = reinterpret_cast<const byte_t*>(mod.modBaseAddr) + dos.e_lfanew;
  if (!ReadProcessMemory(proc, nt_ptr, &nt, sizeof nt, nullptr) ||
      nt.Signature != IMAGE_NT_SIGNATURE)
    return out;

  const WORD count = nt.FileHeader.NumberOfSections;
  if (!count) return out;
  out.resize(count);

  const byte_t* first_sec = nt_ptr + offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
                            nt.FileHeader.SizeOfOptionalHeader;
  ReadProcessMemory(proc, first_sec, out.data(), sizeof(IMAGE_SECTION_HEADER) * count, nullptr);
  return out;
}

[[nodiscard]] inline std::vector<ModuleInfo> list_modules(HANDLE proc) noexcept {
  std::vector<ModuleInfo> out;
  const DWORD pid = GetProcessId(proc);
  const HANDLE snap = CreateToolhelp32Snapshot(k_snap_modules, pid);
  if (snap == INVALID_HANDLE_VALUE) return out;

  MODULEENTRY32 me{sizeof(me)};
  if (Module32First(snap, &me)) {
    do {
      ModuleInfo mi{me, read_sections(proc, me)};
      out.push_back(std::move(mi));
    } while (Module32Next(snap, &me));
  }
  CloseHandle(snap);
  return out;
}

} // namespace utils::process 