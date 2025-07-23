#pragma once

// process.h – minimal Win32 Toolhelp helpers.
// Provides:
//   get_process(std::wstring_view name)             -> optional<PROCESSENTRY32W>
//   get_module(HANDLE proc, std::wstring_view name) -> optional<MODULEENTRY32W>
//   list_modules(HANDLE proc)                       -> vector<ModuleInfo>
// A ModuleInfo contains MODULEENTRY32W and its section headers.

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace utils::process {

constexpr DWORD kSnapModules = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
using byte_t = std::uint8_t;

class Snapshot {
 public:
  Snapshot(DWORD flags, DWORD pid = 0) noexcept
      : handle_(CreateToolhelp32Snapshot(flags, pid)) {}
  Snapshot(const Snapshot&) = delete;
  Snapshot& operator=(const Snapshot&) = delete;
  Snapshot(Snapshot&& other) noexcept : handle_(other.handle_) {
    other.handle_ = INVALID_HANDLE_VALUE;
  }
  Snapshot& operator=(Snapshot&& other) noexcept {
    if (this != &other) {
      reset();
      handle_ = other.handle_;
      other.handle_ = INVALID_HANDLE_VALUE;
    }
    return *this;
  }
  ~Snapshot() { reset(); }

  [[nodiscard]] bool valid() const noexcept {
    return handle_ != INVALID_HANDLE_VALUE;
  }
  [[nodiscard]] HANDLE get() const noexcept { return handle_; }

 private:
  void reset() noexcept {
    if (handle_ != INVALID_HANDLE_VALUE) {
      CloseHandle(handle_);
      handle_ = INVALID_HANDLE_VALUE;
    }
  }

  HANDLE handle_ = INVALID_HANDLE_VALUE;
};

// -------------------------- helpers ----------------------------------------

[[nodiscard]] inline bool iequals(std::wstring_view a, std::wstring_view b) noexcept {
  return _wcsicmp(a.data(), b.data()) == 0;
}

// -------------------------- core API ---------------------------------------

[[nodiscard]] inline std::optional<PROCESSENTRY32W>
get_process(std::wstring_view exe) noexcept {
  Snapshot snap(TH32CS_SNAPPROCESS);
  if (!snap.valid()) return std::nullopt;

  PROCESSENTRY32W entry{sizeof(entry)};
  if (Process32FirstW(snap.get(), &entry)) {
    do {
      if (iequals(entry.szExeFile, exe)) return entry;
    } while (Process32NextW(snap.get(), &entry));
  }
  return std::nullopt;
}

[[nodiscard]] inline std::optional<MODULEENTRY32W>
get_module(HANDLE proc, std::wstring_view name) noexcept {
  const DWORD pid = GetProcessId(proc);
  Snapshot snap(kSnapModules, pid);
  if (!snap.valid()) return std::nullopt;

  MODULEENTRY32W mod{sizeof(mod)};
  if (Module32FirstW(snap.get(), &mod)) {
    do {
      if (iequals(mod.szModule, name)) return mod;
    } while (Module32NextW(snap.get(), &mod));
  }
  return std::nullopt;
}

struct ModuleInfo {
  MODULEENTRY32W mod;
  std::vector<IMAGE_SECTION_HEADER> sections;
};

[[nodiscard]] inline std::vector<IMAGE_SECTION_HEADER>
read_sections(HANDLE proc, const MODULEENTRY32W& mod) noexcept {
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

[[nodiscard]] inline std::vector<ModuleInfo>
list_modules(HANDLE proc) noexcept {
  std::vector<ModuleInfo> out;
  const DWORD pid = GetProcessId(proc);
  Snapshot snap(kSnapModules, pid);
  if (!snap.valid()) return out;

  MODULEENTRY32W me{sizeof(me)};
  if (Module32FirstW(snap.get(), &me)) {
    do {
      ModuleInfo mi{me, read_sections(proc, me)};
      out.push_back(std::move(mi));
    } while (Module32NextW(snap.get(), &me));
  }
  return out;
}

} // namespace utils::process