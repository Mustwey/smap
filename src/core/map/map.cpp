#include "core/map/map.h"

#include <cstdint>
#include <vector>

#include "core/translator/translator.h"   // assumed to exist
#include "utils/file.h"

namespace core::map {

// ---------------------------------------------------------------------------
//  Internal helper – common translator workflow
// ---------------------------------------------------------------------------
namespace {

[[nodiscard]] void* MapWithTranslator(HANDLE                          process,
                                      PBYTE                           base,
                                      const std::vector<core::Region>& regions,
                                      DWORD                           scatter_threshold) {
  void* entry = nullptr;
  Translator translator;

  if (!translator.Initialize(process, base)         ||
      !translator.Align(regions, scatter_threshold) ||
      !translator.Resolve()                         ||
      !translator.Map(entry)) {
    translator.Fail();
    return nullptr;
  }
  return entry;
}

}  // namespace

// ---------------------------------------------------------------------------
//  Public API
// ---------------------------------------------------------------------------
void* IntoRegions(HANDLE process,
                  PBYTE  base,
                  const std::vector<core::Region>& regions,
                  DWORD scatter_threshold) {
  return MapWithTranslator(process, base, regions, scatter_threshold);
}

void* IntoRegions(HANDLE process,
                  const wchar_t* file_path,
                  const std::vector<core::Region>& regions,
                  DWORD scatter_threshold) {
  auto bytes = utils::io::ReadFile(file_path);
  if (!bytes) return nullptr;

  // The buffer must stay valid while the translator mutates it.
  return MapWithTranslator(process,
                           bytes->data(),   // PBYTE base
                           regions,
                           scatter_threshold);
}

}  // namespace core::map 