#pragma once

#include <Windows.h>
#include <vector>
#include <cstdint>

namespace core {

class Region {
 public:
  Region() = default;
  Region(PVOID address, SIZE_T size) noexcept
      : base_(reinterpret_cast<PBYTE>(address)), size_(static_cast<DWORD>(size)) {}
  Region(UINT_PTR address, SIZE_T size) noexcept
      : base_(reinterpret_cast<PBYTE>(address)), size_(static_cast<DWORD>(size)) {}
  Region(PVOID start, PVOID end) noexcept
      : base_(reinterpret_cast<PBYTE>(start)),
        size_(static_cast<DWORD>(reinterpret_cast<PBYTE>(end) - reinterpret_cast<PBYTE>(start))) {}

  void Start(PVOID ptr) noexcept { base_ = reinterpret_cast<PBYTE>(ptr); }
  PBYTE Start() const noexcept { return base_; }

  void End(PVOID ptr) noexcept {
    size_ = static_cast<DWORD>(reinterpret_cast<PBYTE>(ptr) - base_);
  }
  PBYTE End() const noexcept { return base_ + size_; }

  DWORD Size() const noexcept { return size_; }
  void Size(DWORD sz) noexcept { size_ = sz; }

  bool Contains(PVOID addr) const noexcept {
    return reinterpret_cast<PBYTE>(addr) >= base_ && reinterpret_cast<PBYTE>(addr) < End();
  }

  bool ContainsInclusive(PVOID addr) const noexcept {
    return reinterpret_cast<PBYTE>(addr) >= base_ && reinterpret_cast<PBYTE>(addr) <= End();
  }

  std::vector<Region> ResolveConflict(const Region& other) const;
  std::vector<Region> ResolveConflicts(const std::vector<Region>& others) const;

 private:
  PBYTE base_ = nullptr;
  DWORD size_ = 0;
};

}  // namespace core 