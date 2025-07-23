#pragma once

// assemble.h – minimal x86-64 assembler helpers using AsmJit + AsmTK.
//  assemble(const char* asm_text)        -> optional<vector<uint8_t>>
//  assemble_fmt(const char* fmt, ...)    -> same, printf style

#include <asmjit/core.h>
#include <asmjit/x86.h>
#include <asmtk/asmtk.h>

#include <cstdarg>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace utils::assemble {

constexpr size_t k_stack_buf = 512;

[[nodiscard]] inline std::optional<std::vector<uint8_t>>
assemble(std::string_view text) noexcept {
  asmjit::CodeHolder code;
  if (code.init(asmjit::Environment::host()) != asmjit::kErrorOk)
    return std::nullopt;

  asmjit::x86::Assembler assembler(&code);
  asmtk::AsmParser parser(&assembler);
  if (parser.parse(text.data(), text.size()) != asmjit::kErrorOk)
    return std::nullopt;

  if (code.flatten() != asmjit::kErrorOk)
    return std::nullopt;

  std::vector<uint8_t> out(code.codeSize());
  if (code.copyFlattenedData(out.data(), out.size()) != asmjit::kErrorOk)
    return std::nullopt;

  return out;
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
