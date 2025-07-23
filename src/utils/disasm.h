#pragma once

// disasm.h – minimal Zydis helpers (decode/format/regs).

#include <Zydis/Zydis.h>
#include <optional>
#include <string>
#include <bitset>

namespace utils::disasm {

// decoder / formatter singletons ------------------------------------------------
inline const ZydisDecoder& decoder() {
  static ZydisDecoder d;
  static bool init = (ZydisDecoderInit(&d, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64), true);
  (void)init;
  return d;
}
inline const ZydisFormatter& formatter() {
  static ZydisFormatter f;
  static bool init = (ZydisFormatterInit(&f, ZYDIS_FORMATTER_STYLE_INTEL),
                      ZydisFormatterSetProperty(&f, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE), true);
  (void)init;
  return f;
}

// core -------------------------------------------------------------------------
[[nodiscard]] inline std::optional<ZydisDecodedInstruction>
decode(const void* code, size_t size) noexcept {
  ZydisDecodedInstruction inst{};
  if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder(), code, size, &inst)))
    return inst;
  return std::nullopt;
}

template <typename Fn>
inline void for_operands(const ZydisDecodedInstruction& inst, Fn&& fn) noexcept {
  for (uint8_t i = 0; i < inst.operand_count; ++i) {
    const auto& op = inst.operands[i];
    if (op.visibility != ZYDIS_OPERAND_VISIBILITY_HIDDEN) fn(op);
  }
}

[[nodiscard]] inline std::string
format(const ZydisDecodedInstruction& inst, const void* addr = nullptr) noexcept {
  char buf[128]{};
  ZydisFormatterFormatInstruction(&formatter(), &inst, buf, sizeof buf, reinterpret_cast<uint64_t>(addr));
  return {buf};
}

// register helpers -------------------------------------------------------------
inline constexpr ZydisRegister to_64(ZydisRegister r) noexcept {
  return (r >= ZYDIS_REGISTER_AX && r <= ZYDIS_REGISTER_R15)
             ? static_cast<ZydisRegister>(((r - ZYDIS_REGISTER_AX) % 15) + ZYDIS_REGISTER_RAX)
             : r;
}

inline constexpr bool same_register(ZydisRegister a, ZydisRegister b) noexcept {
  return to_64(a) == to_64(b);
}

inline ZydisRegister unused_gp(const ZydisDecodedInstruction& inst) noexcept {
  static constexpr ZydisRegister all[15] = {
      ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RBX,
      ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_R8,
      ZYDIS_REGISTER_R9,  ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11, ZYDIS_REGISTER_R12,
      ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15};

  std::bitset<15> used;
  for_operands(inst, [&](const ZydisDecodedOperand& op){
    if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
      ZydisRegister r = to_64(op.reg.value);
      for (size_t i = 0; i < 15; ++i) if (all[i] == r) used.set(i);
    } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
      ZydisRegister b = to_64(op.mem.base), i = to_64(op.mem.index);
      for (size_t n = 0; n < 15; ++n) if (all[n] == b || all[n] == i) used.set(n);
    }
  });
  for (size_t i = 0; i < 15; ++i) if (!used.test(i)) return all[i];
  return ZYDIS_REGISTER_NONE;
}

[[nodiscard]] inline std::optional<uint64_t>
absolute(const ZydisDecodedInstruction& inst, const void* rva) noexcept {
  std::optional<uint64_t> result;
  for_operands(inst, [&](const ZydisDecodedOperand& op){
    if ((op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) || op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
      uint64_t abs;
      if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, &op, reinterpret_cast<uint64_t>(rva), &abs))) {
        result = abs;
      }
    }
  });
  return result;
}

// quick classification ----------------------------------------------------------
inline bool is_branch(const ZydisDecodedInstruction& inst) noexcept {
  return inst.meta.category == ZYDIS_CATEGORY_COND_BR || inst.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
}

inline bool is_call(const ZydisDecodedInstruction& inst) noexcept {
  return inst.meta.category == ZYDIS_CATEGORY_CALL;
}

} // namespace utils::disasm 