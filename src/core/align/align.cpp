#include "core/align/align.h"

#include <vector>
#include <memory>
#include <algorithm>

#include "utils/pe.h"
#include "utils/process.h"

namespace core::align {

using utils::pe::IsExecutablePage;
using utils::pe::IsInvalidAlignmentSection;
using utils::process::ModuleInfo;
using utils::process::list_modules;

namespace {

[[nodiscard]] std::vector<Region>
GetInvalidSectionRegions(const std::vector<ModuleInfo>& modules) {
  std::vector<Region> regions;
  for (const auto& mod : modules) {
    for (const auto& sec : mod.sections) {
      if (IsInvalidAlignmentSection(sec)) {
        regions.emplace_back(mod.mod.modBaseAddr + sec.VirtualAddress,
                             sec.Misc.VirtualSize);
      }
    }
  }
  return regions;
}

[[nodiscard]] std::vector<Region>
FindRegionAlignments(HANDLE process, const Region& region) {
  std::vector<Region> out;
  if (region.Size() < kMinAlignment) return out;

  std::unique_ptr<uint8_t[]> buf(new uint8_t[region.Size()]);
  if (!ReadProcessMemory(process, region.Start(), buf.get(), region.Size(), nullptr))
    return out;

  const size_t last = region.Size() - kMinAlignment;
  for (size_t i = 0; i <= last;) {
    for (size_t j = 0; j < kMinAlignment; ++j) {
      if (buf[i + j] != kAlignmentByte) {
        ++i;
        goto next;
      }
    }

    Region align(region.Start() + i, kMinAlignment);
    i += kMinAlignment;
    while (i < region.Size() && buf[i] == kAlignmentByte) {
      align.Size(align.Size() + 1);
      ++i;
    }
    out.push_back(align);
  next:;
  }

  return out;
}

} // namespace

std::vector<Region> FindAlignments(HANDLE process) {
  std::vector<Region> out;
  const auto modules = list_modules(process);
  const auto invalid = GetInvalidSectionRegions(modules);

  MEMORY_BASIC_INFORMATION mbi{};
  for (PBYTE addr = nullptr; VirtualQueryEx(process, addr, &mbi, sizeof(mbi));
       addr += mbi.RegionSize) {
    if (!IsExecutablePage(mbi.Protect)) continue;

    Region region(mbi.BaseAddress, mbi.RegionSize);
    const auto valid = region.ResolveConflicts(invalid);
    for (const auto& r : valid) {
      auto aligns = FindRegionAlignments(process, r);
      out.insert(out.end(), aligns.begin(), aligns.end());
    }
  }
  return out;
}

std::vector<Region> FindAlignmentsInModules(HANDLE process) {
  std::vector<Region> out;
  const auto modules = list_modules(process);
  const auto invalid = GetInvalidSectionRegions(modules);

  for (const auto& mod : modules) {
    const PBYTE end = mod.mod.modBaseAddr + mod.mod.modBaseSize;
    MEMORY_BASIC_INFORMATION mbi{};
    for (PBYTE addr = mod.mod.modBaseAddr;
         addr < end && VirtualQueryEx(process, addr, &mbi, sizeof(mbi));
         addr += mbi.RegionSize) {
      if (!IsExecutablePage(mbi.Protect)) continue;

      Region region(mbi.BaseAddress, mbi.RegionSize);
      if (region.End() > end) region.End(end);

      const auto valid = region.ResolveConflicts(invalid);
      for (const auto& r : valid) {
        auto aligns = FindRegionAlignments(process, r);
        out.insert(out.end(), aligns.begin(), aligns.end());
      }
    }
  }
  return out;
}

}  // namespace core::align 