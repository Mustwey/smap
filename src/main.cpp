#include "main.h"

#include <cctype>
#include <cwchar>
#include <string>
#include <vector>

#include "core/align/align.h"
#include "core/hijack/hijack.h"
#include "core/map/map.h"
#include "utils/log.h"
#include "utils/process.h"

using utils::log::errorf;
using utils::log::infof;

namespace {

[[nodiscard]] bool is_number(const wchar_t* s) noexcept {
  for (; *s; ++s)
    if (!std::iswdigit(*s)) return false;
  return true;
}

[[nodiscard]] HANDLE open_target(const std::wstring& id) noexcept {
  DWORD pid = 0;
  if (is_number(id.c_str())) {
    pid = std::wcstoul(id.c_str(), nullptr, 10);
  } else {
    auto pe = utils::process::get_process(id);
    if (!pe) {
      errorf("[!] process %ls not found\n", id.c_str());
      return nullptr;
    }
    pid = pe->th32ProcessID;
  }

  HANDLE h = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!h) errorf("[!] OpenProcess failed (%lu)\n", GetLastError());
  return h;
}

}  // namespace

namespace app {

int run(int argc, wchar_t* argv[]) {
  if (argc < 3) {
    infof("usage: smap <pid|process_name> <pe_path> [iat|hook]\n");
    return 1;
  }

  const std::wstring target = argv[1];
  const std::wstring pe_path = argv[2];
  const bool use_hook = (argc >= 4 && _wcsicmp(argv[3], L"hook") == 0);

  HANDLE proc = open_target(target);
  if (!proc) return 1;

  infof("[+] finding alignment regions…\n");
  auto regions = core::align::FindAlignments(proc);
  if (regions.empty()) {
    infof("[~] none found in free memory, scanning modules…\n");
    regions = core::align::FindAlignmentsInModules(proc);
  }
  if (regions.empty()) {
    errorf("[!] no suitable regions for mapping\n");
    CloseHandle(proc);
    return 1;
  }
  infof("[+] %zu candidate regions\n", regions.size());

  infof("[+] mapping %ls…\n", pe_path.c_str());
  void* entry = core::map::IntoRegions(proc, pe_path.c_str(), regions);
  if (!entry) {
    errorf("[!] mapping failed\n");
    CloseHandle(proc);
    return 1;
  }
  infof("[+] remote entry @ %p\n", entry);

  bool ok = false;
  if (use_hook) {
    infof("[+] hijack via export hook (Sleep)…\n");
    ok = core::hijack::ViaHook(proc, entry, L"kernel32.dll", "Sleep");
  } else {
    infof("[+] hijack via IAT (Sleep)…\n");
    ok = core::hijack::ViaIAT(proc, entry, "Sleep", nullptr);
  }

  if (!ok) {
    errorf("[!] hijack failed\n");
    CloseHandle(proc);
    return 1;
  }

  infof("[+] done\n");
  CloseHandle(proc);
  return 0;
}

}  // namespace app

int wmain(int argc, wchar_t* argv[]) { return app::run(argc, argv); }
