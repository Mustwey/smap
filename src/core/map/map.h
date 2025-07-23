#pragma once

#include <Windows.h>
#include <vector>

#include "core/region/region.h"

namespace core::map {

// Map an already-loaded PE image (pointed to by `base`) into `process`
// using the supplied scratch `regions`.  Returns the remote entry point
// (or nullptr on failure).  The image buffer is **modified in-place**.
[[nodiscard]] void* IntoRegions(HANDLE              process,
                                PBYTE               base,
                                const std::vector<core::Region>& regions,
                                DWORD               scatter_threshold = 1);

// Convenience overload: loads a PE from disk first, then maps it with the
// same semantics as the in-memory overload above.
[[nodiscard]] void* IntoRegions(HANDLE              process,
                                const wchar_t*      file_path,
                                const std::vector<core::Region>& regions,
                                DWORD               scatter_threshold = 1);

}  // namespace core::map 