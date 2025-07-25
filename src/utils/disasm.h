#pragma once

// disasm.h – Zydis-based decoding helpers + register utilities + jump helpers.
// Provides:
//   decode / operands / format
//   same_register, unused_gp, absolute
//   jump_size(...) – choose 2 / 5 / 14-byte JMP length between addresses

#include <Zydis/Zydis.h>
#include <algorithm>
#include <array>
#include <bitset>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace utils::disasm {

// ---------------------------------------------------------------------------
//  Decoder / formatter singletons
// ---------------------------------------------------------------------------
[[nodiscard]] inline const ZydisDecoder& decoder() noexcept {
  static ZydisDecoder d;
  static bool init =
      (ZydisDecoderInit(&d, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64),
       true);
  (void)init;
  return d;
}
[[nodiscard]] inline const ZydisFormatter& formatter() noexcept {
  static ZydisFormatter f;
  static bool init =
      (ZydisFormatterInit(&f, ZYDIS_FORMATTER_STYLE_INTEL),
       ZydisFormatterSetProperty(&f, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE),
       true);
  (void)init;
  return f;
}

// ---------------------------------------------------------------------------
//  Decoding helpers
// ---------------------------------------------------------------------------
[[nodiscard]] inline std::optional<ZydisDecodedInstruction>
decode(const void* code, size_t size) noexcept {
  size = std::min<size_t>(size, ZYDIS_MAX_INSTRUCTION_LENGTH);
  ZydisDecodedInstruction inst{};
  if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder(), code, size, &inst)))
    return inst;
  return std::nullopt;
}
[[nodiscard]] inline std::optional<ZydisDecodedInstruction>
decode(const void* code) noexcept {
  return decode(code, ZYDIS_MAX_INSTRUCTION_LENGTH);
}
[[nodiscard]] inline std::optional<ZydisDecodedInstruction>
decode(std::span<const uint8_t> bytes) noexcept {
  return decode(bytes.data(), bytes.size());
}

template <typename Fn>
inline void for_operands(const ZydisDecodedInstruction& inst, Fn&& fn) noexcept {
  for (uint8_t i = 0; i < inst.operand_count; ++i) {
    const auto& op = inst.operands[i];
    if (op.visibility != ZYDIS_OPERAND_VISIBILITY_HIDDEN) fn(op);
  }
}
[[nodiscard]] inline std::vector<ZydisDecodedOperand>
operands(const ZydisDecodedInstruction& inst) noexcept {
  std::vector<ZydisDecodedOperand> out;
  for_operands(inst, [&](const ZydisDecodedOperand& op) { out.push_back(op); });
  return out;
}
[[nodiscard]] inline std::string
format(const ZydisDecodedInstruction& inst, const void* addr = nullptr) noexcept {
  char buf[128]{};
  ZydisFormatterFormatInstruction(&formatter(), &inst, buf, sizeof buf,
                                  reinterpret_cast<uint64_t>(addr));
  return {buf};
}

// ---------------------------------------------------------------------------
//  Register helpers
// ---------------------------------------------------------------------------
constexpr size_t k_gp_count = (ZYDIS_REGISTER_R15 - ZYDIS_REGISTER_RAX) + 1;
inline constexpr ZydisRegister to_64(ZydisRegister r) noexcept {
  return (r >= ZYDIS_REGISTER_AX && r <= ZYDIS_REGISTER_R15)
             ? static_cast<ZydisRegister>(((r - ZYDIS_REGISTER_AX) % k_gp_count) +
                                          ZYDIS_REGISTER_RAX)
             : r;
}
inline constexpr bool same_register(ZydisRegister a, ZydisRegister b) noexcept {
  return to_64(a) == to_64(b);
}
[[nodiscard]] inline std::optional<ZydisRegister>
unused_gp(const ZydisDecodedInstruction& inst) noexcept {
  static constexpr std::array<ZydisRegister, 15> k_gp_regs = {
      ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX,
      ZYDIS_REGISTER_RBX, ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_RSI,
      ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_R8,  ZYDIS_REGISTER_R9,
      ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11, ZYDIS_REGISTER_R12,
      ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15};
  std::bitset<k_gp_regs.size()> used;
  for_operands(inst, [&](const ZydisDecodedOperand& op) {
    if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
      const ZydisRegister r = to_64(op.reg.value);
      for (size_t i = 0; i < k_gp_regs.size(); ++i)
        if (k_gp_regs[i] == r) used.set(i);
    } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
      const ZydisRegister b = to_64(op.mem.base);
      const ZydisRegister i = to_64(op.mem.index);
      for (size_t n = 0; n < k_gp_regs.size(); ++n)
        if (k_gp_regs[n] == b || k_gp_regs[n] == i) used.set(n);
    }
  });
  for (size_t i = 0; i < k_gp_regs.size(); ++i)
    if (!used.test(i)) return k_gp_regs[i];
  return std::nullopt;
}
[[nodiscard]] inline std::optional<uint64_t>
absolute(const ZydisDecodedInstruction& inst, const void* rva) noexcept {
  std::optional<uint64_t> result;
  for_operands(inst, [&](const ZydisDecodedOperand& op) {
    if ((op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) ||
        op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
      uint64_t abs;
      if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, &op,
                                                reinterpret_cast<uint64_t>(rva),
                                                &abs)))
        result = abs;
    }
  });
  return result;
}

// ---------------------------------------------------------------------------
//  Quick classification helpers
// ---------------------------------------------------------------------------
inline bool is_branch(const ZydisDecodedInstruction& inst) noexcept {
  return inst.meta.category == ZYDIS_CATEGORY_COND_BR ||
         inst.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
}
inline bool is_call(const ZydisDecodedInstruction& inst) noexcept {
  return inst.meta.category == ZYDIS_CATEGORY_CALL;
}
inline bool is_ret(const ZydisDecodedInstruction& inst) noexcept {
  return inst.meta.category == ZYDIS_CATEGORY_RET;
}

// ---------------------------------------------------------------------------
//  Jump-size helper (2/5/14-byte)
// ---------------------------------------------------------------------------
[[nodiscard]] inline uint32_t jump_size(const void* dest, const void* src) noexcept {
  const auto diff =
      static_cast<const uint8_t*>(dest) - static_cast<const uint8_t*>(src);
  if (std::abs(diff - 2) <= 0x7F) return 2;        // short
  if (std::abs(diff - 5) <= 0x7FFFFFFF) return 5;  // near
  return 14;                                       // absolute
}

} // namespace utils::disasm 
