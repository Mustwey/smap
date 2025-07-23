#include "core/smap/smap.h"

#include <cstdio>
#include <utility>
#include <vector>

#include "core/align/align.h"
#include "core/hijack/hijack.h"
#include "core/map/map.h"

namespace core {

SMap::SMap(DWORD process_id,
           std::wstring dll_path,
           std::wstring target_module,
           std::string target_function,
           DWORD scatter_threshold,
           bool use_iat) noexcept
    : process_id_(process_id),
      dll_path_(std::move(dll_path)),
      target_module_(std::move(target_module)),
      target_function_(std::move(target_function)),
      scatter_threshold_(scatter_threshold ? scatter_threshold : 1),
      use_iat_(use_iat) {
  if (target_function_.empty()) target_function_ = "PeekMessageW";
  if (!use_iat_ && target_module_.empty()) target_module_ = L"user32.dll";
}

SMap::~SMap() {
  if (process_handle_) {
    CloseHandle(process_handle_);
    process_handle_ = nullptr;
  }
}

bool SMap::Inject() {
  if (process_handle_) {
    CloseHandle(process_handle_);
    process_handle_ = nullptr;
  }

  process_handle_ = OpenProcess(PROCESS_QUERY_INFORMATION |
                                PROCESS_VM_OPERATION |
                                PROCESS_VM_READ |
                                PROCESS_VM_WRITE,
                                FALSE, process_id_);
  if (!process_handle_) {
    std::fprintf(stderr, "[-] failed to open process %lu\n", process_id_);
    return false;
  }

  auto regions = core::align::FindAlignmentsInModules(process_handle_);
  void* entry = core::map::IntoRegions(process_handle_,
                                       dll_path_.c_str(),
                                       regions,
                                       scatter_threshold_);
  if (!entry) return false;

  const wchar_t* mod = target_module_.empty() ? nullptr : target_module_.c_str();
  const char* fn = target_function_.empty() ? "PeekMessageW" : target_function_.c_str();

  bool ok = use_iat_
      ? core::hijack::ViaIAT(process_handle_, entry, fn, mod)
      : core::hijack::ViaHook(process_handle_, entry, mod, fn);

  if (ok) std::printf("[-] injection complete\n");
  return ok;
}

}  // namespace core 