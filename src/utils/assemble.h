#pragma once

// assemble.h – minimal x86-64 assembler helpers using AsmJit + AsmTK.
//  assemble(const char* asm_text)        -> optional<vector<uint8_t>>
//  assemble_fmt(const char* fmt, ...)    -> same, printf style

#include <asmjit/asmjit.h>
#include <asmtk/asmtk.h>

#include <cstdarg>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace utils::assemble {

constexpr size_t k_stack_buf = 512;

[[nodiscard]] inline std::optional<std::vector<uint8_t>>
assemble(std::string_view text) noexcept {
  asmjit::CodeHolder code;
  code.init(asmjit::CodeInfo(asmjit::ArchInfo::kIdX64));

  asmjit::x86::Assembler a(&code);
  asmtk::AsmParser p(&a);
  if (p.parse(text.data())) return std::nullopt;

  const auto& buf = code.sectionById(0)->buffer();
  return std::vector<uint8_t>(buf.data(), buf.data() + buf.size());
}

[[nodiscard]] inline std::optional<std::vector<uint8_t>>
assemble(const char* text) noexcept {
  return assemble(std::string_view{text});
}

[[nodiscard]] inline std::optional<std::vector<uint8_t>>
assemble_fmt(const char* fmt, ...) noexcept {
  char stack[k_stack_buf];
  va_list ap;
  va_start(ap, fmt);
  int len = vsnprintf(stack, sizeof(stack), fmt, ap);
  va_end(ap);
  if (len < 0) return std::nullopt;

  if (static_cast<size_t>(len) < sizeof(stack))
    return assemble(std::string_view{stack, static_cast<size_t>(len)});

  std::string dyn(len + 1, '\0');
  va_start(ap, fmt);
  vsnprintf(dyn.data(), dyn.size(), fmt, ap);
  va_end(ap);
  // dyn.data() already null-terminated
  return assemble(std::string_view{dyn.data(), static_cast<size_t>(len)});
}

} // namespace utils::assemble 