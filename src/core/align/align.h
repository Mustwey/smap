#pragma once

#include <Windows.h>
#include <vector>
#include "core/region/region.h"

namespace core::align {

constexpr size_t kMinAlignment = 14;
constexpr uint8_t kAlignmentByte = 0xCC;

std::vector<Region> FindAlignments(HANDLE process);
std::vector<Region> FindAlignmentsInModules(HANDLE process);

}  // namespace core::align 