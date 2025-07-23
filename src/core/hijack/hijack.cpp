#include "core/hijack/hijack.h"

#include <Psapi.h>
#include <array>
#include <memory>

#include "utils/pe.h"
#include "utils/process.h"

namespace core::hijack {

using utils::pe::FindImportEntry;
using utils::process::get_module;

// ---------------------------------------------------------------------------
//  Small helpers / RAII
// ---------------------------------------------------------------------------
namespace {

struct ScopedProtect {
  HANDLE proc;
  void*  addr;
  std::size_t size;
  DWORD old{};

  ScopedProtect(HANDLE p, void* a, std::size_t s, DWORD prot)  //
      : proc(p), addr(a), size(s) {
    VirtualProtectEx(proc, addr, size, prot, &old);
  }
  ~ScopedProtect() { VirtualProtectEx(proc, addr, size, old, &old); }
};

[[nodiscard]] std::wstring GetMainModuleName(HANDLE proc) {
  wchar_t buf[MAX_PATH]{};
  GetModuleBaseNameW(proc, nullptr, buf, std::size(buf));
  return {buf};
}

}  // namespace

// ---------------------------------------------------------------------------
//  IAT hijack
// ---------------------------------------------------------------------------
bool ViaIAT(HANDLE process,
            void*  entry,
            const char* import_name,
            const wchar_t* module) {
  const std::wstring target =
      (module && *module) ? module : GetMainModuleName(process);

  auto iat_entry = FindImportEntry(process, target, import_name);
  if (!iat_entry) return false;

  // 69-byte self-patching stub (same layout as in your reference).
  std::array<std::uint8_t, 69> shell = {
      0x00, 0x48, 0xB8,                         // mov rax, <iat_entry>
      /*[ 3 ..10]*/ 0,0,0,0,0,0,0,0,
      0x48, 0xBA,                               // mov rdx, [orig_ptr]
      /*[13..20]*/ 0,0,0,0,0,0,0,0,
      0x48, 0x89, 0x10,                         // mov [rax], rdx
      0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 0x28
      0x48, 0xBA,                               // mov rdx, <entry>
      /*[30..37]*/ 0x01,0,0,0,0,0,0,0,
      0xFF, 0x15, 0x02, 0x00, 0x00, 0x00,       // call qword ptr [rip+2]
      0xEB, 0x08,                               // jmp <done>
      /*[46..53]*/ 0,0,0,0,0,0,0,0,             // (slot for <entry>)
      0x48, 0x83, 0xC4, 0x28,                   // add rsp, 0x28
      0x48, 0x31, 0xC0,                         // xor rax, rax
      0x80, 0x05, 0xBC, 0xFF, 0xFF, 0xFF, 0x01, // add byte [rip-0x44], 1
      0xC3                                      // ret
  };

  // Patch placeholders.
  *reinterpret_cast<void**>(&shell[3])  = *iat_entry;
  ReadProcessMemory(process, *iat_entry, &shell[13], sizeof(void*), nullptr);
  *reinterpret_cast<void**>(&shell[46]) = entry;

  auto remote =
      static_cast<std::uint8_t*>(VirtualAllocEx(process, nullptr, shell.size(),
                                                MEM_COMMIT | MEM_RESERVE,
                                                PAGE_EXECUTE_READWRITE));
  if (!remote) return false;

  WriteProcessMemory(process, remote, shell.data(), shell.size(), nullptr);

  // Swap IAT pointer → stub (+1 to skip the status byte).
  ScopedProtect protect(process, *iat_entry, sizeof(void*), PAGE_READWRITE);
  void* stub_entry = remote + 1;
  WriteProcessMemory(process, *iat_entry, &stub_entry, sizeof(stub_entry),
                     nullptr);

  // Wait until stub writes the original pointer back.
  for (void* cur = stub_entry; cur == stub_entry; Sleep(1))
    if (!ReadProcessMemory(process, *iat_entry, &cur, sizeof(cur), nullptr)) {
      VirtualFreeEx(process, remote, 0, MEM_RELEASE);
      return false;
    }

  // Wait for the status-byte set by the stub.
  for (std::uint8_t status = 0; status == 0; Sleep(1))
    if (!ReadProcessMemory(process, remote, &status, sizeof(status), nullptr)) {
      VirtualFreeEx(process, remote, 0, MEM_RELEASE);
      return false;
    }

  VirtualFreeEx(process, remote, 0, MEM_RELEASE);
  return true;
}

// ---------------------------------------------------------------------------
//  “inline-hook” hijack (trampoline)
// ---------------------------------------------------------------------------
bool ViaHook(HANDLE process,
             void*  entry,
             const wchar_t* module_name,
             const char* function_name) {
  auto remote_mod = get_module(process, module_name);
  if (!remote_mod) return false;

  const HMODULE local = LoadLibraryW(module_name);
  if (!local) return false;

  auto* local_func =
      reinterpret_cast<std::uint8_t*>(GetProcAddress(local, function_name));
  if (!local_func) return false;

  auto* remote_func =
      remote_mod->modBaseAddr +
      (local_func - reinterpret_cast<std::uint8_t*>(local));

  // 79-byte stub (same layout as in your reference).
  std::array<std::uint8_t, 79> shell = {
      0x00, 0x48, 0xB8,                         // mov rax, <remote_func>
      /*[ 3 ..10]*/ 0,0,0,0,0,0,0,0,
      0x48, 0xBA,                               // mov rdx, [orig_qword1]
      /*[13..20]*/ 0,0,0,0,0,0,0,0,
      0x48, 0x89, 0x10,                         // mov [rax], rdx
      0x48, 0xBA,                               // mov rdx, [orig_qword2]
      /*[26..33]*/ 0,0,0,0,0,0,0,0,
      0x48, 0x89, 0x50, 0x08,                   // mov [rax+8], rdx
      0x48, 0x83, 0xEC, 0x28,                   // sub rsp, 0x28
      0x48, 0xBA,                               // mov rdx, <entry>
      /*[44..51]*/ 0x01,0,0,0,0,0,0,0,
      0xFF, 0x15, 0x02, 0x00, 0x00, 0x00,       // call qword ptr [rip+2]
      0xEB, 0x08,                               // jmp <done>
      /*[60..67]*/ 0,0,0,0,0,0,0,0,
      0x48, 0x83, 0xC4, 0x28,                   // add rsp, 0x28
      0x48, 0x31, 0xC0,                         // xor rax, rax
      0xC6, 0x05, 0xAE, 0xFF, 0xFF, 0xFF, 0x01, // mov byte [rip-0x52], 1
      0xC3                                      // ret
  };

  *reinterpret_cast<void**>(&shell[3]) = remote_func;
  ReadProcessMemory(process, remote_func, &shell[13], sizeof(std::uint64_t),
                    nullptr);
  ReadProcessMemory(process, remote_func + sizeof(std::uint64_t),
                    &shell[26], sizeof(std::uint64_t), nullptr);
  *reinterpret_cast<void**>(&shell[60]) = entry;

  auto remote =
      static_cast<std::uint8_t*>(VirtualAllocEx(process, nullptr, shell.size(),
                                                MEM_COMMIT | MEM_RESERVE,
                                                PAGE_EXECUTE_READWRITE));
  if (!remote) return false;

  WriteProcessMemory(process, remote, shell.data(), shell.size(), nullptr);

  // Encode absolute JMP [RIP+0] → remote+1.
  std::array<std::uint8_t, 14> jmp = {0xFF, 0x25, 0, 0, 0, 0};
  *reinterpret_cast<void**>(&jmp[6]) = remote + 1;

  ScopedProtect protect(process, remote_func, 2 * sizeof(std::uint64_t),
                        PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(process, remote_func, jmp.data(), jmp.size(), nullptr);

  // Wait until stub restores the original bytes.
  for (std::uint64_t cur = 0; cur == 0; Sleep(1))
    if (!ReadProcessMemory(process, remote_func + 6, &cur, sizeof(cur),
                           nullptr)) {
      VirtualFreeEx(process, remote, 0, MEM_RELEASE);
      return false;
    }

  // Wait for status.
  for (std::uint8_t status = 0; status == 0; Sleep(1))
    if (!ReadProcessMemory(process, remote, &status, sizeof(status), nullptr)) {
      VirtualFreeEx(process, remote, 0, MEM_RELEASE);
      return false;
    }

  VirtualFreeEx(process, remote, 0, MEM_RELEASE);
  return true;
}

}  // namespace core::hijack
