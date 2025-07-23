#pragma once

#include <Windows.h>
#include <string>

namespace core {

class SMap {
 public:
  SMap(DWORD process_id,
       std::wstring dll_path,
       std::wstring target_module = L"user32.dll",
       std::string target_function = "PeekMessageW",
       DWORD scatter_threshold = 1,
       bool use_iat = false) noexcept;

  ~SMap();

  SMap(const SMap&) = delete;
  SMap& operator=(const SMap&) = delete;

  [[nodiscard]] bool Inject();

 private:
  HANDLE process_handle_ = nullptr;
  DWORD process_id_ = 0;

  std::wstring dll_path_;
  std::wstring target_module_;
  std::string target_function_;

  DWORD scatter_threshold_ = 1;
  bool use_iat_ = false;
};

}  // namespace core 