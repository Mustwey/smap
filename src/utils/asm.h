#pragma once

#include <Zydis/Zydis.h>
#include <asmjit/asmjit.h>
#include <asmtk/asmtk.h>

#include <vector>
#include <string>
#include <memory>
#include <optional>
#include <unordered_map>
#include <cstdint>
#include <span>

namespace utils::asm {

// ============================================================================
// Forward Declarations & Types
// ============================================================================

using ByteCode = std::vector<uint8_t>;
using Address = std::uintptr_t;

enum class Architecture { X86, X64 };
enum class EmitterType { Assembler, Builder, Compiler };

// ============================================================================
// Zydis Decoder Wrapper - Full Feature Set
// ============================================================================

class Decoder {
private:
    ZydisDecoder decoder_;
    ZydisFormatter formatter_;
    Architecture arch_;
    bool initialized_ = false;

public:
    explicit Decoder(Architecture arch = Architecture::X64) : arch_(arch) {
        auto machine_mode = (arch == Architecture::X64) ? 
            ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
        auto stack_width = (arch == Architecture::X64) ?
            ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32;
            
        initialized_ = ZYAN_SUCCESS(ZydisDecoderInit(&decoder_, machine_mode, stack_width)) &&
                      ZYAN_SUCCESS(ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL));
    }

    struct Instruction {
        ZydisDecodedInstruction instruction;
        std::vector<ZydisDecodedOperand> operands;
        Address runtime_address = 0;
        
        bool is_valid() const noexcept { 
            return instruction.mnemonic != ZYDIS_MNEMONIC_INVALID; 
        }
        
        bool is_relative() const noexcept {
            return instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE;
        }
        
        bool is_branch() const noexcept {
            return instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
                   instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                   instruction.meta.category == ZYDIS_CATEGORY_CALL ||
                   instruction.meta.category == ZYDIS_CATEGORY_RET;
        }
        
        bool is_call() const noexcept {
            return instruction.meta.category == ZYDIS_CATEGORY_CALL;
        }
        
        bool is_jump() const noexcept {
            return instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
                   instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
        }
        
        bool is_conditional() const noexcept {
            return instruction.meta.category == ZYDIS_CATEGORY_COND_BR;
        }
        
        bool has_memory_operand() const noexcept {
            return std::any_of(operands.begin(), operands.end(),
                [](const auto& op) { return op.type == ZYDIS_OPERAND_TYPE_MEMORY; });
        }
        
        std::optional<Address> get_branch_target() const noexcept {
            if (!is_branch() || operands.empty()) return std::nullopt;
            
            Address target = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operands[0], 
                                                     runtime_address, &target))) {
                return target;
            }
            return std::nullopt;
        }
        
        std::vector<ZydisRegister> get_read_registers() const {
            std::vector<ZydisRegister> regs;
            for (const auto& op : operands) {
                if (op.actions & ZYDIS_OPERAND_ACTION_READ) {
                    if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                        regs.push_back(op.reg.value);
                    } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                        if (op.mem.base != ZYDIS_REGISTER_NONE) 
                            regs.push_back(op.mem.base);
                        if (op.mem.index != ZYDIS_REGISTER_NONE)
                            regs.push_back(op.mem.index);
                    }
                }
            }
            return regs;
        }
        
        std::vector<ZydisRegister> get_written_registers() const {
            std::vector<ZydisRegister> regs;
            for (const auto& op : operands) {
                if (op.actions & ZYDIS_OPERAND_ACTION_WRITE && 
                    op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    regs.push_back(op.reg.value);
                }
            }
            return regs;
        }
    };

    std::optional<Instruction> decode(std::span<const uint8_t> data, 
                                     Address runtime_address = 0) const {
        if (!initialized_ || data.empty()) return std::nullopt;
        
        Instruction result;
        result.runtime_address = runtime_address;
        
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder_, data.data(), data.size(),
                                               &result.instruction, 
                                               result.operands.data()))) {
            return std::nullopt;
        }
        
        result.operands.resize(result.instruction.operand_count_visible);
        return result;
    }
    
    std::string format(const Instruction& inst) const {
        if (!initialized_) return {};
        
        char buffer[256];
        if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter_, 
                                                        &inst.instruction,
                                                        inst.operands.data(),
                                                        inst.operands.size(),
                                                        buffer, sizeof(buffer),
                                                        inst.runtime_address))) {
            return std::string(buffer);
        }
        return {};
    }
    
    // Advanced analysis
    std::vector<Instruction> disassemble_block(std::span<const uint8_t> data,
                                              Address start_address = 0) const {
        std::vector<Instruction> instructions;
        size_t offset = 0;
        
        while (offset < data.size()) {
            auto inst = decode(data.subspan(offset), start_address + offset);
            if (!inst || !inst->is_valid()) break;
            
            instructions.push_back(*inst);
            offset += inst->instruction.length;
            
            // Stop at unconditional branches
            if (inst->is_branch() && !inst->is_conditional()) break;
        }
        
        return instructions;
    }
};

// ============================================================================
// Register Analysis Utilities
// ============================================================================

namespace registers {
    inline bool is_same_register(ZydisRegister a, ZydisRegister b) noexcept {
        if (a == b) return true;
        
        // Handle register aliasing (e.g., EAX/RAX/AX/AL)
        auto get_largest = [](ZydisRegister reg) -> ZydisRegister {
            if (reg >= ZYDIS_REGISTER_AL && reg <= ZYDIS_REGISTER_R15B) {
                // 8-bit registers
                auto base = (reg - ZYDIS_REGISTER_AL) % 16;
                return static_cast<ZydisRegister>(ZYDIS_REGISTER_RAX + base);
            } else if (reg >= ZYDIS_REGISTER_AX && reg <= ZYDIS_REGISTER_R15W) {
                // 16-bit registers  
                auto base = (reg - ZYDIS_REGISTER_AX) % 16;
                return static_cast<ZydisRegister>(ZYDIS_REGISTER_RAX + base);
            } else if (reg >= ZYDIS_REGISTER_EAX && reg <= ZYDIS_REGISTER_R15D) {
                // 32-bit registers
                auto base = (reg - ZYDIS_REGISTER_EAX) % 16;
                return static_cast<ZydisRegister>(ZYDIS_REGISTER_RAX + base);
            }
            return reg;
        };
        
        return get_largest(a) == get_largest(b);
    }
    
    inline ZydisRegister find_unused_register(const std::vector<ZydisRegister>& used_regs,
                                            Architecture arch = Architecture::X64) {
        std::vector<ZydisRegister> candidates;
        
        if (arch == Architecture::X64) {
            candidates = {
                ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX,
                ZYDIS_REGISTER_RBX, ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_RSI,
                ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_R8,  ZYDIS_REGISTER_R9,
                ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11, ZYDIS_REGISTER_R12,
                ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15
            };
        } else {
            candidates = {
                ZYDIS_REGISTER_EAX, ZYDIS_REGISTER_ECX, ZYDIS_REGISTER_EDX,
                ZYDIS_REGISTER_EBX, ZYDIS_REGISTER_EBP, ZYDIS_REGISTER_ESI,
                ZYDIS_REGISTER_EDI
            };
        }
        
        for (auto candidate : candidates) {
            bool is_used = std::any_of(used_regs.begin(), used_regs.end(),
                [candidate](ZydisRegister used) {
                    return is_same_register(candidate, used);
                });
            if (!is_used) return candidate;
        }
        
        return ZYDIS_REGISTER_NONE;
    }
}

// ============================================================================
// AsmJit Code Generator - Full Feature Set  
// ============================================================================

class Generator {
private:
    asmjit::Environment env_;
    asmjit::CpuFeatures features_;
    Architecture arch_;
    
public:
    explicit Generator(Architecture arch = Architecture::X64) : arch_(arch) {
        if (arch == Architecture::X64) {
            env_ = asmjit::Environment::host();
        } else {
            env_ = asmjit::Environment(asmjit::Arch::kX86);
        }
        features_ = asmjit::CpuFeatures::host();
    }
    
    // Generate code using Assembler (direct emission)
    std::optional<ByteCode> assemble(const std::string& assembly_text) {
        asmjit::CodeHolder code;
        if (code.init(env_, features_) != asmjit::kErrorOk) return std::nullopt;
        
        asmjit::x86::Assembler assembler(&code);
        asmtk::AsmParser parser(&assembler);
        
        if (parser.parse(assembly_text.c_str()) != asmjit::kErrorOk) {
            return std::nullopt;
        }
        
        auto& buffer = code.sectionById(0)->buffer();
        return ByteCode(buffer.data(), buffer.data() + buffer.size());
    }
    
    // Generate code using Builder (node-based, optimizable)
    std::optional<ByteCode> assemble_optimized(const std::string& assembly_text) {
        asmjit::CodeHolder code;
        if (code.init(env_, features_) != asmjit::kErrorOk) return std::nullopt;
        
        asmjit::x86::Builder builder(&code);
        asmtk::AsmParser parser(&builder);
        
        if (parser.parse(assembly_text.c_str()) != asmjit::kErrorOk) {
            return std::nullopt;
        }
        
        // Finalize builder to assembler
        asmjit::x86::Assembler assembler(&code);
        if (builder.finalize() != asmjit::kErrorOk) return std::nullopt;
        
        auto& buffer = code.sectionById(0)->buffer();
        return ByteCode(buffer.data(), buffer.data() + buffer.size());
    }
    
    // Generate shellcode with specific target address
    ByteCode create_jump_shellcode(Address target_address) {
        asmjit::CodeHolder code;
        code.init(env_, features_);
        
        asmjit::x86::Assembler a(&code);
        
        if (arch_ == Architecture::X64) {
            // JMP [RIP+0] followed by target address  
            a.db(0xFF, 0x25, 0x00, 0x00, 0x00, 0x00);
            a.embedUInt64(target_address);
        } else {
            // JMP target_address
            a.jmp(asmjit::imm(target_address));
        }
        
        auto& buffer = code.sectionById(0)->buffer();
        return ByteCode(buffer.data(), buffer.data() + buffer.size());
    }
    
    ByteCode create_call_shellcode(Address target_address) {
        asmjit::CodeHolder code;
        code.init(env_, features_);
        
        asmjit::x86::Assembler a(&code);
        
        if (arch_ == Architecture::X64) {
            // CALL [RIP+2] followed by JMP over address, then target address
            a.db(0xFF, 0x15, 0x02, 0x00, 0x00, 0x00);  // CALL [RIP+2]
            a.db(0xEB, 0x08);                           // JMP +8
            a.embedUInt64(target_address);
        } else {
            a.call(asmjit::imm(target_address));
        }
        
        auto& buffer = code.sectionById(0)->buffer();
        return ByteCode(buffer.data(), buffer.data() + buffer.size());
    }
    
    // Advanced: Convert conditional jump to absolute addressing
    std::optional<ByteCode> convert_conditional_jump(ZydisMnemonic mnemonic, 
                                                     Address target_address) {
        asmjit::CodeHolder code;
        code.init(env_, features_);
        
        asmjit::x86::Assembler a(&code);
        
        // Get the opposite condition for short jump over absolute jump
        auto get_opposite = [](ZydisMnemonic mn) -> asmjit::x86::Inst::Id {
            switch (mn) {
                case ZYDIS_MNEMONIC_JZ:  return asmjit::x86::Inst::kIdJnz;
                case ZYDIS_MNEMONIC_JNZ: return asmjit::x86::Inst::kIdJz;
                case ZYDIS_MNEMONIC_JL:  return asmjit::x86::Inst::kIdJnl;
                case ZYDIS_MNEMONIC_JLE: return asmjit::x86::Inst::kIdJnle;
                case ZYDIS_MNEMONIC_JG:  return asmjit::x86::Inst::kIdJng;
                case ZYDIS_MNEMONIC_JGE: return asmjit::x86::Inst::kIdJnge;
                case ZYDIS_MNEMONIC_JB:  return asmjit::x86::Inst::kIdJnb;
                case ZYDIS_MNEMONIC_JBE: return asmjit::x86::Inst::kIdJnbe;
                case ZYDIS_MNEMONIC_JA:  return asmjit::x86::Inst::kIdJna;
                case ZYDIS_MNEMONIC_JAE: return asmjit::x86::Inst::kIdJnae;
                default: return asmjit::x86::Inst::kIdNone;
            }
        };
        
        auto opposite = get_opposite(mnemonic);
        if (opposite == asmjit::x86::Inst::kIdNone) return std::nullopt;
        
        auto skip_label = a.newLabel();
        a.emit(opposite, skip_label);              // Jump over if condition not met
        
        // Emit absolute jump to target
        if (arch_ == Architecture::X64) {
            a.db(0xFF, 0x25, 0x00, 0x00, 0x00, 0x00);
            a.embedUInt64(target_address);
        } else {
            a.jmp(asmjit::imm(target_address));
        }
        
        a.bind(skip_label);
        
        auto& buffer = code.sectionById(0)->buffer();
        return ByteCode(buffer.data(), buffer.data() + buffer.size());
    }
};

// ============================================================================
// Instruction Transformation Engine
// ============================================================================

class Transformer {
private:
    Decoder decoder_;
    Generator generator_;
    Architecture arch_;
    
public:
    explicit Transformer(Architecture arch = Architecture::X64) 
        : decoder_(arch), generator_(arch), arch_(arch) {}
    
    struct TransformResult {
        ByteCode code;
        size_t original_size;
        Address next_instruction_address;
        bool needs_relocation = false;
        Address relocation_target = 0;
    };
    
    // Transform relative instruction to absolute
    std::optional<TransformResult> make_absolute(std::span<const uint8_t> instruction_bytes,
                                                Address instruction_address) {
        auto inst = decoder_.decode(instruction_bytes, instruction_address);
        if (!inst || !inst->is_valid()) return std::nullopt;
        
        TransformResult result;
        result.original_size = inst->instruction.length;
        result.next_instruction_address = instruction_address + inst->instruction.length;
        
        if (!inst->is_relative()) {
            // Not relative, return as-is
            result.code = ByteCode(instruction_bytes.begin(), instruction_bytes.end());
            return result;
        }
        
        auto target = inst->get_branch_target();
        if (!target) return std::nullopt;
        
        result.needs_relocation = true;
        result.relocation_target = *target;
        
        // Generate absolute version based on instruction type
        if (inst->instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
            result.code = generator_.create_jump_shellcode(*target);
        } else if (inst->instruction.mnemonic == ZYDIS_MNEMONIC_CALL) {
            result.code = generator_.create_call_shellcode(*target);
        } else if (inst->is_conditional()) {
            auto abs_code = generator_.convert_conditional_jump(inst->instruction.mnemonic, *target);
            if (!abs_code) return std::nullopt;
            result.code = *abs_code;
        } else {
            // LEA or other relative instruction - use register-based approach
            auto used_regs = inst->get_read_registers();
            auto unused_reg = registers::find_unused_register(used_regs, arch_);
            
            if (unused_reg == ZYDIS_REGISTER_NONE) return std::nullopt;
            
            std::string reg_name = (arch_ == Architecture::X64) ? "r11" : "eax"; // fallback
            
            std::string asm_code = "mov " + reg_name + ", " + std::to_string(*target);
            auto mov_code = generator_.assemble(asm_code);
            if (!mov_code) return std::nullopt;
            
            result.code = *mov_code;
        }
        
        return result;
    }
    
    // Advanced: Analyze and transform instruction sequences
    std::vector<TransformResult> transform_sequence(std::span<const uint8_t> code_block,
                                                   Address start_address) {
        std::vector<TransformResult> results;
        auto instructions = decoder_.disassemble_block(code_block, start_address);
        
        size_t offset = 0;
        for (const auto& inst : instructions) {
            auto inst_bytes = code_block.subspan(offset, inst.instruction.length);
            auto transform = make_absolute(inst_bytes, start_address + offset);
            
            if (transform) {
                results.push_back(*transform);
            }
            
            offset += inst.instruction.length;
        }
        
        return results;
    }
};

// ============================================================================
// High-Level Interface
// ============================================================================

// Convenience functions for common operations
inline std::optional<Decoder::Instruction> decode(std::span<const uint8_t> data, 
                                                  Address addr = 0,
                                                  Architecture arch = Architecture::X64) {
    Decoder decoder(arch);
    return decoder.decode(data, addr);
}

inline std::string format(const Decoder::Instruction& inst, 
                         Architecture arch = Architecture::X64) {
    Decoder decoder(arch);
    return decoder.format(inst);
}

inline std::optional<ByteCode> assemble(const std::string& assembly_text,
                                       Architecture arch = Architecture::X64) {
    Generator generator(arch);
    return generator.assemble(assembly_text);
}

inline ZydisRegister get_unused_register(const std::vector<ZydisRegister>& used_regs,
                                        Architecture arch = Architecture::X64) {
    return registers::find_unused_register(used_regs, arch);
}

} // namespace utils::asm 