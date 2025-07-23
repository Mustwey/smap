#include "core/region/region.h"

namespace core {

std::vector<Region> Region::ResolveConflict(const Region& other) const {
  std::vector<Region> out;

  if (other.ContainsInclusive(Start()) && other.ContainsInclusive(End()))
    return out;

  const bool contains_start = ContainsInclusive(other.Start());
  const bool contains_end = ContainsInclusive(other.End());

  if (Start() == other.Start() && contains_end) {
    out.emplace_back(other.End() + 1, End());
  } else if (End() == other.End() && contains_start) {
    out.emplace_back(Start(), other.Start() - 1);
  } else if (contains_start && contains_end) {
    out.emplace_back(Start(), other.Start() - 1);
    out.emplace_back(other.End() + 1, End());
  } else if (contains_start) {
    out.emplace_back(Start(), other.Start() - 1);
  } else if (contains_end) {
    out.emplace_back(other.End() + 1, End());
  } else {
    out.push_back(*this);
  }

  return out;
}

std::vector<Region> Region::ResolveConflicts(const std::vector<Region>& others) const {
  std::vector<Region> resolved{*this};

  for (const auto& r : others) {
    std::vector<Region> temp;
    for (const auto& current : resolved) {
      auto parts = current.ResolveConflict(r);
      temp.insert(temp.end(), parts.begin(), parts.end());
    }
    resolved.swap(temp);
  }

  return resolved;
}

}  // namespace core 