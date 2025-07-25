// Translator implementation.
// Cleaned up to follow Google C++ style and remove redundancies.

#include "core/translator/translator.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <regex>
#include <string>

#include "core/align/align.h"
#include "core/translation/translation.h"
#include "utils/assemble.h"
#include "utils/disasm.h"
#include "utils/log.h"
#include "utils/pe.h"
#include "utils/process.h"

using utils::log::errorf;
using utils::log::infof;

namespace {

struct ScopedProtect {
  HANDLE proc;
  void *addr;
  std::size_t size;
  DWORD old{};
  ScopedProtect(HANDLE p, void *a, std::size_t s, DWORD prot)
      : proc{p}, addr{a}, size{s} {
    ::VirtualProtectEx(proc, addr, size, prot, &old);
  }
  ~ScopedProtect() {
    DWORD tmp;
    ::VirtualProtectEx(proc, addr, size, old, &tmp);
  }
};

} // unnamed namespace

namespace core {

// Begins code analysis on the PE
bool Translator::Initialize(HANDLE process, PBYTE base) {
  auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    errorf("invalid DOS signature\n");
    return false;
  }

  auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    errorf("invalid NT signature\n");
    return false;
  }

  nt->Signature = dos->e_magic = 0;

  this->process_handle_ = process;
  this->image_base_ = base;
  this->nt_headers_ = nt;

  if (!this->MapHeaders()) {
    return false;
  }

  infof("[-] analyzing sections...\n");
  auto section = IMAGE_FIRST_SECTION(nt);
  for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
    try {
      this->AddSection(base, section);
    } catch (INT) {
      return false;
    }
  }

  return true;
}

// Maps the headers into the target process
bool Translator::MapHeaders() {
  auto sizeOfHeaders = this->nt_headers_->OptionalHeader.SizeOfHeaders;
  auto mapped = VirtualAllocEx(this->Process(), nullptr, sizeOfHeaders,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!mapped) {
    errorf("failed to allocate virtual memory for headers\n");
    return false;
  }

  this->AddTranslation(new RegionTranslation(
      Region(0ULL, sizeOfHeaders), mapped, this->image_base_, sizeOfHeaders));
  return true;
}

// Returns a vector of RVAs for each PE export
std::vector<PVOID> Translator::GetExports() {
  std::vector<PVOID> exports;

  auto rva = this->nt_headers_->OptionalHeader
                 .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                 .VirtualAddress;
  if (!rva) {
    return exports;
  }

  auto exportDirectory = this->TranslateRaw<PIMAGE_EXPORT_DIRECTORY>(rva);
  if (!exportDirectory) {
    return exports;
  }

  auto addressOfFunctions =
      this->TranslateRaw<PULONG>(exportDirectory->AddressOfFunctions);
  if (!addressOfFunctions) {
    return exports;
  }

  auto addressOfNameOrdinals =
      this->TranslateRaw<PUSHORT>(exportDirectory->AddressOfNameOrdinals);
  if (!addressOfNameOrdinals) {
    return exports;
  }

  for (auto i = 0UL; i < exportDirectory->NumberOfNames; ++i) {
    exports.push_back(reinterpret_cast<PVOID>(
        static_cast<UINT_PTR>(addressOfFunctions[addressOfNameOrdinals[i]])));
  }

  return exports;
}

// Resolves the PE's imports
bool Translator::ResolveImports() {
  infof("[+] imports\n");

  auto rva = this->nt_headers_->OptionalHeader
                 .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                 .VirtualAddress;
  if (!rva) {
    return true;
  }

  auto importDescriptor = this->TranslateRaw<PIMAGE_IMPORT_DESCRIPTOR>(rva);
  if (!importDescriptor) {
    return true;
  }

  for (; importDescriptor->FirstThunk; ++importDescriptor) {
    auto moduleName = this->TranslateRaw<PCHAR>(importDescriptor->Name);
    if (!moduleName) {
      break;
    }

    auto module = LoadLibraryA(moduleName);
    if (!module) {
      errorf("failed to load module: %s\n", moduleName);
      return false;
    }

    auto remoteOpt = utils::process::get_module(
        this->Process(),
        std::wstring(moduleName, moduleName + strlen(moduleName)));
    if (!remoteOpt) {
      errorf("target process does not have %s loaded\n", moduleName);
      return false;
    }
    auto processModule = remoteOpt->mod.modBaseAddr;

    for (auto thunk = this->TranslateRaw<PIMAGE_THUNK_DATA>(
             importDescriptor->FirstThunk);
         thunk->u1.AddressOfData; ++thunk) {
      auto importByName =
          this->TranslateRaw<PIMAGE_IMPORT_BY_NAME>(thunk->u1.AddressOfData);

      thunk->u1.Function = reinterpret_cast<UINT_PTR>(
          processModule +
          (reinterpret_cast<PBYTE>(GetProcAddress(module, importByName->Name)) -
           reinterpret_cast<PBYTE>(module)));
    }
  }

  return true;
}

// Resolves the PE's relocations
bool Translator::ResolveRelocations() {
  infof("[+] relocations\n");

  auto &baseRelocDir = this->nt_headers_->OptionalHeader
                           .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (!baseRelocDir.VirtualAddress) {
    return true;
  }

  auto reloc =
      this->TranslateRaw<PIMAGE_BASE_RELOCATION>(baseRelocDir.VirtualAddress);
  if (!reloc) {
    return true;
  }

  for (auto currentSize = 0UL; currentSize < baseRelocDir.Size;) {
    auto relocCount =
        (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
    auto relocData = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(reloc) +
                                             sizeof(IMAGE_BASE_RELOCATION));
    auto relocBase = this->TranslateRaw<PBYTE>(reloc->VirtualAddress);

    for (auto i = 0UL; i < relocCount; ++i, ++relocData) {
      auto data = *relocData;
      auto type = data >> 12;
      auto offset = data & 0xFFF;

      switch (type) {
      case IMAGE_REL_BASED_ABSOLUTE:
        break;
      case IMAGE_REL_BASED_DIR64: {
        auto &rva = *reinterpret_cast<PVOID *>(relocBase + offset);

        rva =
            this->Translate(reinterpret_cast<PBYTE>(rva) -
                            reinterpret_cast<PBYTE>(
                                this->nt_headers_->OptionalHeader.image_base_));

        break;
      }
      default:
        errorf("unsupported relocation type: %d\n", type);
        return false;
      }
    }

    currentSize += reloc->SizeOfBlock;
    reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(relocData);
  }

  return true;
}

// Returns the next jump size from the dest to src including instruction length
static DWORD NextJumpSize(void *dest, void *src) {
  const auto diff = std::llabs(reinterpret_cast<std::intptr_t>(dest) -
                               reinterpret_cast<std::intptr_t>(src));
  if (diff <= 0x7F - kJumpShortSize)
    return kJumpShortSize;
  if (diff <= 0x7FFFFFFF - kJumpNearSize)
    return kJumpNearSize;
  return kJumpAbsoluteSize;
}

// Returns the next jump size from one region to another
static DWORD NextJumpSize(const std::vector<Region> &regions, std::size_t i,
                          std::size_t end) {
  if (i >= end - 1)
    return kJumpAbsoluteSize;
  auto diff = reinterpret_cast<std::intptr_t>(regions[i + 1].Start()) -
              reinterpret_cast<std::intptr_t>(regions[i].End());
  diff = std::llabs(diff);

  if (diff <= 0x7F)
    return kJumpShortSize;
  if (diff <= 0x7FFFFFFF)
    return kJumpNearSize;
  return kJumpAbsoluteSize;
}

// Aligns an export in the given alignment regions
Translation *Translator::AlignExport(std::size_t &translation_index,
                                     std::size_t translations_count,
                                     const std::vector<Region> &regions,
                                     std::size_t region_begin,
                                     std::size_t region_end) {
  std::size_t regionIndex = region_begin;
  auto regionOffset = 0UL;

  for (; translation_index < translations_count; ++translation_index) {
    auto &translation = this->translations_[translation_index];
    if (!translation->Executable()) {
      continue;
    }

    auto region = &regions[regionIndex];
    auto jumpSize = NextJumpSize(regions, regionIndex, region_end);
    while (regionOffset + translation->BufferSize() + jumpSize >
           region->Size()) {
      if (regionIndex == region_end - 1) {
        goto leftover;
      }

      auto leftoverSize = region->Size() - regionOffset;
      auto jumpBuffer = new BYTE[leftoverSize];
      auto jumpIndex = leftoverSize - jumpSize;

      memset(jumpBuffer, 0x90, jumpIndex);

      auto jumpInst = &jumpBuffer[jumpIndex];
      auto jumpDest = regions[regionIndex + 1].Start();

      switch (jumpSize) {
      case 2:
        jumpInst[0] = 0xEB;
        jumpInst[1] = static_cast<CHAR>(jumpDest - region->End());
        break;
      case 5:
        jumpInst[0] = 0xE9;
        *reinterpret_cast<PINT>(&jumpInst[1]) =
            static_cast<INT>(jumpDest - region->End());
        break;
      case 14:
        memcpy(jumpInst, "\xFF\x25\x00\x00\x00\x00", 6);
        *reinterpret_cast<PVOID *>(&jumpInst[6]) = jumpDest;
        break;
      }

      auto jump =
          new ModifiedTranslation(Region(-1, 0UL), jumpBuffer, leftoverSize);
      jump->Mapped(region->Start() + regionOffset);
      this->AddTranslation(jump);

      region = &regions[++regionIndex];
      regionOffset = 0;
      jumpSize = NextJumpSize(regions, regionIndex, region_end);
    }

    translation->Mapped(region->Start() + regionOffset);
    regionOffset += translation->BufferSize();
  }

  return nullptr;

leftover:
  auto jumpBuffer = new BYTE[14]{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
  auto jump = new ModifiedTranslation(Region(-1, 0UL), jumpBuffer, 14);
  jump->Mapped(regions[regionIndex].Start() + regionOffset);
  this->AddTranslation(jump);

  return jump;
}

// Aligns the translations in the given alignment regions or newly created RX
// regions
bool Translator::Align(const std::vector<Region> &regions,
                       DWORD scatter_threshold) {
  infof("\n[-] aligning code map\n");

  auto exports = this->GetExports();
  if (exports.size() == 0) {
    infof("[+] no exports found\n");
  } else {
    infof("[+] found %lld exports\n", exports.size());

    if (regions.size() < exports.size()) {
      errorf("needed at least %lld regions, had %lld\n", exports.size(),
             regions.size());
      return false;
    }
  }

  auto translations_count = this->translations_.size();

  // Evenly distribute region alignments among exports
  auto regionIncrement =
      exports.size() == 0 ? 0 : regions.size() / exports.size();

  PBYTE scatterBase = nullptr;
  auto scatterIndex = 0ULL;
  Translation *lastJump = nullptr;

  for (auto i = 0ULL; i < translations_count; ++i) {
    auto translation = this->translations_[i].get();
    if (!translation->Executable()) {
      continue;
    }

    // Align any exports if the current translation is one
    for (auto e = 0ULL; e < exports.size(); ++e) {
      if (exports[e] == translation->RVA().Start()) {
        auto regionStart = e * regionIncrement;
        auto regionEnd = (e == exports.size() - 1 ? regions.size()
                                                  : (e + 1) * regionIncrement);

        auto exportStart = regions[regionStart].Start();
        infof("[+] export %lld > %p\n", e, exportStart);

        lastJump = this->AlignExport(i, translations_count, regions,
                                     regionStart, regionEnd);
        if (!lastJump) {
          return true;
        }

        translation = this->translations_[i].get();
        scatterIndex = 0;
        scatterBase = nullptr;
        break;
      }
    }

    if (scatterIndex == scatter_threshold) {
      auto jumpBuffer = new BYTE[14]{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
      auto jump = new ModifiedTranslation(Region(-1, 0UL), jumpBuffer, 14);
      jump->Mapped(scatterBase);
      this->AddTranslation(jump);

      lastJump = jump;

      scatterIndex = 0;
      scatterBase = nullptr;
    }

    if (scatterBase) {
      translation->Mapped(scatterBase);

      ++scatterIndex;
      scatterBase += translation->BufferSize();
    } else {
      auto scatterSize = 14ULL;
      for (auto e = i; e < i + scatter_threshold && e < translations_count;
           ++e) {
        auto &t = this->translations_[e];
        if (e > i && std::find(exports.begin(), exports.end(),
                               t->RVA().Start()) != exports.end()) {
          break;
        }

        scatterSize += t->BufferSize();
      }

      scatterBase = reinterpret_cast<PBYTE>(
          VirtualAllocEx(this->Process(), nullptr, scatterSize,
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ));
      if (!scatterBase) {
        errorf("failed to allocate virtual memory\n");
        return false;
      }

      if (lastJump) {
        auto buffer = static_cast<PBYTE>(lastJump->Buffer());
        auto jumpSize = NextJumpSize(scatterBase, lastJump->Mapped());

        switch (jumpSize) {
        case 2:
          buffer[0] = 0xEB;
          buffer[1] = static_cast<CHAR>(scatterBase - (lastJump->Mapped() + 2));
          break;
        case 5:
          buffer[0] = 0xE9;
          *reinterpret_cast<PINT>(&buffer[1]) =
              static_cast<INT>(scatterBase - (lastJump->Mapped() + 5));
          break;
        case 14:
          *reinterpret_cast<PVOID *>(&buffer[6]) = scatterBase;
          break;
        }
      }

      translation->Mapped(scatterBase, true);

      ++scatterIndex;
      scatterBase += translation->BufferSize();
    }
  }

  return true;
}

// Resolves all relative references
bool Translator::Resolve() {
  infof("\n[-] resolving...\n");

  if (!this->ResolveImports()) {
    return false;
  }

  if (!this->ResolveRelocations()) {
    return false;
  }

  infof("[+] relative instructions and jump tables\n");
  for (auto &translation : this->translations_) {
    if (!translation->Resolve(*this)) {
      errorf("failed to resolve %p\n", translation->RVA().Start());
      return false;
    }
  }

  return true;
}

// Maps the aligned code into the target process
bool Translator::Map(PVOID &entry) {
  infof("\n[-] mapping sections & code map\n");

  for (auto &t : this->translations_) {
    if (!t->BufferSize()) {
      continue;
    }

    ProtectGuard pg{this->Process(), t->Mapped(), t->BufferSize(),
                    PAGE_EXECUTE_READWRITE};
    if (!pg.Success()) {
      errorf("protect RWX failed\n");
      return false;
    }

    if (!WriteProcessMemory(this->Process(), t->Mapped(), t->Buffer(),
                            t->BufferSize(), nullptr)) {
      errorf("WriteProcessMemory failed @%p\n", t->Mapped());
      return false;
    }
  }

  infof("[+] mapped %zu translations\n", this->translations_.size());

  entry = this->Translate(reinterpret_cast<PVOID>(
      this->nt_headers_->OptionalHeader.AddressOfEntryPoint));
  infof("[+] entry point: %p\n", entry);
  return true;
}

// Returns the section header for the RVA
PIMAGE_SECTION_HEADER Translator::TranslateRawSection(PVOID rva) {
  auto section = IMAGE_FIRST_SECTION(this->nt_headers_);
  for (auto i = 0; i < this->nt_headers_->FileHeader.NumberOfSections;
       ++i, ++section) {
    if (Region(section->VirtualAddress, section->Misc.VirtualSize)
            .Contains(rva)) {
      return section;
    }
  }

  return nullptr;
}

// Returns the virtual RVA for the raw RVA
PVOID Translator::TranslateRaw(PVOID rva) {
  auto section = this->TranslateRawSection(rva);
  if (!section) {
    return nullptr;
  }

  return this->image_base_ + section->PointerToRawData +
         (reinterpret_cast<PBYTE>(rva) -
          reinterpret_cast<PBYTE>(
              static_cast<UINT_PTR>(section->VirtualAddress)));
}

// Returns the mapped VA for the virtual RVA
PVOID Translator::Translate(PVOID rva) {
  auto size = static_cast<LONG64>(this->translations_.size());
  if (size == 0) {
    return nullptr;
  }

  auto left = 0LL;
  auto right = size - 1;
  while (left <= right) {
    auto middle = (left + right) / 2;
    auto trans = this->translations_[middle].get();
    if (trans->RVA().Contains(rva)) {
      while (middle - 1 >= 0 &&
             this->translations_[middle - 1].get()->RVA().Contains(rva)) {
        --middle;
      }

      trans = this->translations_[middle].get();
      return trans->Mapped() +
             (reinterpret_cast<PBYTE>(rva) - trans->RVA().Start());
    }

    if (trans->RVA().Start() > rva) {
      right = middle - 1;
    } else {
      left = middle + 1;
    }
  }

  return nullptr;
}

// Adds a section for code analysis
void Translator::AddSection(PBYTE base, PIMAGE_SECTION_HEADER section) {
  if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
    infof("[+] %-8s > (0x%X, 0x%X)\n", section->Name, section->VirtualAddress,
          section->SizeOfRawData);
    this->AddExecuteSection(base, section);
  } else {
    auto mapped =
        VirtualAllocEx(this->Process(), nullptr, section->Misc.VirtualSize,
                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mapped) {
      errorf("failed to allocate virtual memory for %s section\n",
             section->Name);
      throw TranslatorException();
    }

    infof("[+] %-8s > %p (0x%X, 0x%X)\n", section->Name, mapped,
          section->VirtualAddress, section->Misc.VirtualSize);
    this->AddTranslation(new RegionTranslation(
        Region(section->VirtualAddress, section->Misc.VirtualSize), mapped,
        base + section->PointerToRawData,
        std::min(section->Misc.VirtualSize, section->SizeOfRawData)));
  }
}

// Traces backwards to find the first xref to the current translation at
// translationIndex
void Translator::TraceBranch(int &translation_index, int starting_index) {
  auto rva = this->translations_[translation_index]->RVA();

  auto branch = this->branches_.find(rva.Start());
  if (branch != this->branches_.end()) {
    auto xref = branch->second;
    if (xref < rva.Start()) {
      for (; translation_index >= starting_index; --translation_index) {
        if (this->translations_[translation_index]->RVA().Start() == xref) {
          break;
        }
      }

      while (
          translation_index - 1 >= starting_index &&
          this->translations_[static_cast<std::size_t>(translation_index) - 1]
                  ->RVA()
                  .Start() == xref) {
        --translation_index;
      }
    }
  }
}

// Returns whether the given register refers to an absolute location in the PE
bool Translator::IsRegisterAbsolute(ZydisRegister reg, int translation_index,
                                    int starting_index, void *&absolute) {
  if (utils::disasm::same_register(reg, ZYDIS_REGISTER_RSP)) {
    return false;
  }

  for (auto i = translation_index; i >= starting_index; --i) {
    auto prevTrans = this->translations_[i].get();
    if (!prevTrans->Executable()) {
      continue;
    }

    if (i != translation_index) {
      auto prevInst =
          utils::disasm::decode(prevTrans->Buffer(), prevTrans->BufferSize());
      if (prevInst.mnemonic == ZYDIS_MNEMONIC_INT3 ||
          prevInst.mnemonic == ZYDIS_MNEMONIC_INVALID) {
        return false;
      }

      auto relativeTrans = dynamic_cast<RelativeTranslation *>(prevTrans);
      auto prevInstOperands = utils::disasm::operands(prevInst);
      switch (prevInstOperands.size()) {
      case 1:
        if (prevInstOperands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            utils::disasm::same_register(prevInstOperands[0].reg.value, reg)) {
          return false;
        }

        break;
      case 2:
        if (prevInstOperands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            utils::disasm::same_register(prevInstOperands[0].reg.value, reg)) {
          if (relativeTrans && prevInstOperands[1].imm.value.u != 0) {
            absolute = reinterpret_cast<PVOID>(prevInstOperands[1].imm.value.u);
            return true;
          } else {
            return false;
          }
        }

        break;
      }
    }

    this->TraceBranch(i, starting_index);
  }

  return false;
}

// Adds a jump table translation
bool Translator::AddSwitchTranslation(const Region &rva, const BYTE *jmp_buffer,
                                      const ZydisDecodedInstruction &jmp_inst) {
  auto jumpOperands = utils::disasm::operands(jmp_inst);
  if (jumpOperands.size() != 1 ||
      jumpOperands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
    return false;
  }

  auto jumpRegister = jumpOperands[0].reg.value;

  // TODO: clean this up
  struct {
    ZydisRegister Register;
    INT TranslationIndex;
  } offset = {ZYDIS_REGISTER_NONE};

  struct {
    PVOID RVA;
    ZydisDecodedOperand IndexOperand;
    std::vector<PVOID> Entries;
    INT LookupTranslationIndex;
    ZydisDecodedInstruction LookupInstruction;
    std::vector<ZydisDecodedOperand> LookupOperands;
    ULONG64 Cases;
    PVOID Mapped;
    bool JumpAbove, IsRelative;
  } jumpTable = {0};

  struct {
    PVOID RVA;
    BYTE EntrySize;
    INT LookupTranslationIndex;
    ZydisRegister LookupIndexRegister;
    BYTE LookupScale;
    ZydisDecodedInstruction LookupInstruction;
    ULONG64 Cases;
    PVOID Mapped;
  } indirectJumpTable = {0};

  for (INT i = static_cast<INT>(this->translations_.size()) - 1;
       i >= 0 && !jumpTable.Cases && !indirectJumpTable.Cases; --i) {
    auto prevTrans = this->translations_[i].get();
    if (!prevTrans->Executable()) {
      continue;
    }

    auto prevInst =
        utils::disasm::decode(prevTrans->Buffer(), prevTrans->BufferSize());
    if (prevInst.mnemonic == ZYDIS_MNEMONIC_INT3 ||
        prevInst.mnemonic == ZYDIS_MNEMONIC_INVALID) {
      return false;
    }

    auto prevInstOperands = utils::disasm::operands(prevInst);
    if (prevInstOperands.size() != 2) {
      if (!jumpTable.JumpAbove && prevInst.mnemonic == ZYDIS_MNEMONIC_JNBE) {
        jumpTable.JumpAbove = true;
      }

      continue;
    }

    auto &op0 = prevInstOperands[0];
    auto &op1 = prevInstOperands[1];
    if (offset.Register == ZYDIS_REGISTER_NONE) {
      if (op0.type != ZYDIS_OPERAND_TYPE_REGISTER ||
          !utils::disasm::same_register(op0.reg.value, jumpRegister)) {
        continue;
      }

      if (prevInst.mnemonic != ZYDIS_MNEMONIC_ADD) {
        return false;
      }

      if (op1.type != ZYDIS_OPERAND_TYPE_REGISTER) {
        errorf("unexpected instruction with jump register at %p (%p)\n",
               prevTrans->RVA().Start(), rva.Start());
        throw TranslatorException();
      }

      offset.Register = op1.reg.value;
      offset.TranslationIndex = i;
    } else if (jumpTable.IndexOperand.type == ZYDIS_OPERAND_TYPE_UNUSED) {
      if (op0.type != ZYDIS_OPERAND_TYPE_REGISTER ||
          (!utils::disasm::same_register(op0.reg.value, jumpRegister) &&
           !utils::disasm::same_register(op0.reg.value, offset.Register))) {
        continue;
      }

      // (#5) MSVC - optimization for jump cases that use cs:0
      auto prevRelative = dynamic_cast<RelativeTranslation *>(prevTrans);
      if (prevRelative && prevRelative->Pointer() == nullptr &&
          utils::disasm::same_register(op0.reg.value, offset.Register)) {
        continue;
      }

      if (op1.type != ZYDIS_OPERAND_TYPE_MEMORY ||
          op1.mem.index == ZYDIS_REGISTER_NONE || op1.mem.scale != 4) {
        errorf("unexpected instruction with jump/offset register at %p (%p)\n",
               prevTrans->RVA().Start(), rva.Start());
        throw TranslatorException();
      }

      if (op1.mem.disp.has_displacement) {
        jumpTable.RVA = reinterpret_cast<PVOID>(op1.mem.disp.value);
      } else {
        if (this->IsRegisterAbsolute(op1.mem.base, i, 0, jumpTable.RVA)) {
          jumpTable.IsRelative = true;
        } else {
          errorf("failed to trace jump table base register to a valid table "
                 "(%p)\n",
                 rva.Start());
          throw TranslatorException();
        }
      }

      jumpTable.IndexOperand = jumpOperands[0];
      jumpTable.IndexOperand.reg.value = op1.mem.index;

      jumpTable.LookupTranslationIndex = i;
      jumpTable.LookupInstruction = prevInst;
      jumpTable.LookupOperands = prevInstOperands;
    } else {
      if (jumpTable.JumpAbove) {
        // LLVM - override the current index operand if we found a JA and
        // receive a CMP or SUB
        switch (prevInst.mnemonic) {
        case ZYDIS_MNEMONIC_CMP:
        case ZYDIS_MNEMONIC_SUB:
          jumpTable.JumpAbove = false;
          jumpTable.IndexOperand = op0;
          break;
        }
      }

      if (op0 == jumpTable.IndexOperand ||
          (op0.type == jumpTable.IndexOperand.type &&
           op0.type == ZYDIS_OPERAND_TYPE_REGISTER &&
           utils::disasm::same_register(op0.reg.value,
                                        jumpTable.IndexOperand.reg.value))) {
        switch (prevInst.mnemonic) {
        case ZYDIS_MNEMONIC_CMP:
        case ZYDIS_MNEMONIC_AND:
        case ZYDIS_MNEMONIC_MOV:
        case ZYDIS_MNEMONIC_MOVSX:
        case ZYDIS_MNEMONIC_MOVSXD:
        case ZYDIS_MNEMONIC_MOVZX:
        case ZYDIS_MNEMONIC_SUB:
          if (op1.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if (indirectJumpTable.RVA) {
              indirectJumpTable.Cases = op1.imm.value.u + 1;
            } else {
              jumpTable.Cases = op1.imm.value.u + 1;
            }
          } else if (op1.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                     op1.mem.disp.has_displacement &&
                     op1.mem.index != ZYDIS_REGISTER_NONE) {
            jumpTable.IndexOperand = jumpOperands[0];
            jumpTable.IndexOperand.reg.value =
                (op1.mem.index == jumpTable.LookupOperands[1].mem.base
                     ? op1.mem.base
                     : op1.mem.index);

            indirectJumpTable.RVA = reinterpret_cast<PVOID>(op1.mem.disp.value);
            indirectJumpTable.EntrySize = op1.mem.scale;
            indirectJumpTable.LookupTranslationIndex = i;
            indirectJumpTable.LookupInstruction = prevInst;
            indirectJumpTable.LookupIndexRegister =
                jumpTable.IndexOperand.reg.value;
            indirectJumpTable.LookupScale = op1.mem.scale;
          } else {
            jumpTable.IndexOperand = op1;
          }

          break;
        case ZYDIS_MNEMONIC_LEA:
          // LLVM - may decide to use LEA for the case count
          if (op1.type == ZYDIS_OPERAND_TYPE_MEMORY &&
              op1.mem.base != ZYDIS_REGISTER_NONE &&
              op1.mem.disp.has_displacement) {
            if (indirectJumpTable.RVA) {
              indirectJumpTable.Cases = op1.mem.disp.value + 1;
            } else {
              jumpTable.Cases = op1.mem.disp.value + 1;
            }

            break;
          }

          // Intentional fallthrough
        default:
          errorf(
              "unexpected instruction (%p, %s) with index operand while "
              "parsing jump table (%p)",
              prevTrans->RVA().Start(),
              utils::disasm::format(prevInst, prevTrans->RVA().Start()).c_str(),
              rva.Start());
          throw TranslatorException();
        }
      }
    }

    if (!jumpTable.Cases && !indirectJumpTable.Cases) {
      this->TraceBranch(i, 0);
    }
  }

  if (!jumpTable.Cases && !indirectJumpTable.Cases) {
    errorf("failed to find all necessary data for jump table (%p)\n",
           rva.Start());
    throw TranslatorException();
  }

  if (indirectJumpTable.RVA) {
    auto rawIndirectJumpTable =
        this->TranslateRaw<PBYTE>(indirectJumpTable.RVA);
    if (!rawIndirectJumpTable) {
      errorf("failed to translate raw indirect jump table\n");
      throw TranslatorException();
    }

    for (auto i = 0ULL; i < indirectJumpTable.Cases; ++i) {
      auto entry = rawIndirectJumpTable + (i * indirectJumpTable.EntrySize);

      switch (indirectJumpTable.EntrySize) {
      case 1:
        jumpTable.Cases =
            std::max(static_cast<UINT_PTR>(*reinterpret_cast<PBYTE>(entry)),
                     jumpTable.Cases);
        break;
      case 2:
        jumpTable.Cases =
            std::max(static_cast<UINT_PTR>(*reinterpret_cast<PUSHORT>(entry)),
                     jumpTable.Cases);
        break;
      case 4:
        jumpTable.Cases =
            std::max(static_cast<UINT_PTR>(*reinterpret_cast<PUINT>(entry)),
                     jumpTable.Cases);
        break;
      default:
        errorf("bad indirect jump table scale\n");
        throw TranslatorException();
      }
    }

    ++jumpTable.Cases;

    auto rawIndirectJumpTableSize =
        indirectJumpTable.Cases * indirectJumpTable.EntrySize;
    indirectJumpTable.Mapped =
        VirtualAllocEx(this->Process(), nullptr, rawIndirectJumpTableSize,
                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!indirectJumpTable.Mapped) {
      errorf("failed to allocate virtual memory\n");
      throw TranslatorException();
    }

    WriteProcessMemory(this->Process(), indirectJumpTable.Mapped,
                       rawIndirectJumpTable, rawIndirectJumpTableSize, nullptr);

    if (this->TranslateRawSection(indirectJumpTable.RVA)->Characteristics &
        IMAGE_SCN_MEM_EXECUTE) {
      memset(rawIndirectJumpTable, 0xCC, rawIndirectJumpTableSize);
    }
  }

  try {
    for (auto i = 0ULL; i < jumpTable.Cases; ++i) {
      auto entryRva = reinterpret_cast<PBYTE>(jumpTable.RVA) + i * 4;
      auto &entry = *this->TranslateRaw<PULONG>(entryRva);
      if (!entry) {
        errorf("found invalid jump table entry (%p)\n", rva.Start());
        throw TranslatorException();
      }

      if (jumpTable.IsRelative) {
        entry = static_cast<LONG>(entry) +
                static_cast<LONG>(reinterpret_cast<UINT_PTR>(jumpTable.RVA));
      }

      auto dest = reinterpret_cast<PVOID>(static_cast<UINT_PTR>(entry));
      this->AddBranch(dest, rva.Start());
      jumpTable.Entries.push_back(dest);

      if (this->TranslateRawSection(entryRva)->Characteristics &
          IMAGE_SCN_MEM_EXECUTE) {
        entry = 0xCCCCCCCC;
      }
    }

    jumpTable.Mapped = VirtualAllocEx(this->Process(), nullptr,
                                      jumpTable.Entries.size() * sizeof(PVOID),
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!jumpTable.Mapped) {
      errorf("failed to allocate virtual memory\n");
      throw TranslatorException();
    }
  } catch (INT e) {
    if (indirectJumpTable.Mapped) {
      VirtualFreeEx(this->Process(), indirectJumpTable.Mapped, 0, MEM_RELEASE);
    }

    throw e;
  }

  // Prepare to rewrite the jump table
  this->AddTranslation(
      new SwitchTranslation(rva, jumpBuffer, jumpInst.length, jumpTable.Entries,
                            jumpTable.Mapped, indirectJumpTable.Mapped));
  this->RemoveTranslation(offset.TranslationIndex);

  auto lookupRva = this->translations_[jumpTable.LookupTranslationIndex]->RVA();
  auto unusedStr = ZydisRegisterGetString(
      utils::disasm::unused_gp(jumpTable.LookupInstruction));

  // Rewrite the jump register
  this->ReplaceTranslation(
      jumpTable.LookupTranslationIndex++,
      new ModifiedTranslation(lookupRva, "push %s", unusedStr));
  this->InsertTranslation(jumpTable.LookupTranslationIndex++,
                          new ModifiedTranslation(lookupRva, "mov %s, 0x%p",
                                                  unusedStr, jumpTable.Mapped));
  this->InsertTranslation(
      jumpTable.LookupTranslationIndex++,
      new ModifiedTranslation(
          lookupRva, "mov %s, [%s+%s*8]", ZydisRegisterGetString(jumpRegister),
          unusedStr,
          ZydisRegisterGetString(jumpTable.LookupOperands[1].mem.index)));
  this->InsertTranslation(
      jumpTable.LookupTranslationIndex,
      new ModifiedTranslation(lookupRva, "pop %s", unusedStr));

  if (indirectJumpTable.RVA) {
    // Rewrite the indirect jump table reference to be absolute
    lookupRva =
        this->translations_[indirectJumpTable.LookupTranslationIndex]->RVA();
    unusedStr = ZydisRegisterGetString(
        utils::disasm::unused_gp(indirectJumpTable.LookupInstruction));

    this->ReplaceTranslation(
        indirectJumpTable.LookupTranslationIndex++,
        new ModifiedTranslation(lookupRva, "push %s", unusedStr));
    this->InsertTranslation(indirectJumpTable.LookupTranslationIndex++,
                            new ModifiedTranslation(lookupRva, "mov %s, 0x%p",
                                                    unusedStr,
                                                    indirectJumpTable.Mapped));

    auto lookupStr = utils::disasm::format(indirectJumpTable.LookupInstruction,
                                           lookupRva.Start());
    lookupStr = std::regex_replace(lookupStr, std::regex("\\[.*"), "");
    this->InsertTranslation(
        indirectJumpTable.LookupTranslationIndex++,
        new ModifiedTranslation(
            lookupRva, "%s[%s+%s*%d]", lookupStr.c_str(), unusedStr,
            ZydisRegisterGetString(indirectJumpTable.LookupIndexRegister),
            indirectJumpTable.LookupScale));

    this->InsertTranslation(
        indirectJumpTable.LookupTranslationIndex,
        new ModifiedTranslation(lookupRva, "pop %s", unusedStr));
  }

  return true;
}

// Adds a relative instruction translation
void Translator::AddRelativeTranslation(
    const Region &rva, const BYTE *instruction_buffer,
    const ZydisDecodedInstruction &instruction) {
  auto operands = utils::disasm::operands(instruction);
  auto absoluteAddr = utils::disasm::absolute(rva.Start(), instruction);

  switch (instruction.mnemonic) {
  case ZYDIS_MNEMONIC_LEA:
    // Convert relative LEA to absolute

    this->AddTranslation(new RelativeTranslation(
        rva, absoluteAddr, "mov %s, 0x%p",
        ZydisRegisterGetString(operands[0].reg.value), ABSOLUTE_SIG));
    break;
  case ZYDIS_MNEMONIC_JMP:
    // Convert relative direct jump to absolute

    if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
      auto sizeOfRawData = 14;
      auto rawData =
          new BYTE[sizeOfRawData]{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
      auto rvaOffset = 6;
      *reinterpret_cast<PVOID *>(&rawData[rvaOffset]) = absoluteAddr;

      this->AddBranch(absoluteAddr, rva.Start());
      this->AddTranslation(
          new RelativeTranslation(rva, rawData, sizeOfRawData, rvaOffset));
    } else {
      this->AddTranslation(new RelativeTranslation(
          rva, absoluteAddr, "mov r11, 0x%p", ABSOLUTE_SIG));
      this->AddTranslation(new ModifiedTranslation(rva, "jmp [r11]"));
    }

    break;
  case ZYDIS_MNEMONIC_CALL:
    // Convert relative call to absolute

    if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
      auto sizeOfRawData = 16;
      auto rawData = new BYTE[sizeOfRawData]{0xFF, 0x15, 0x02, 0x00, 0x00, 0x00,
                                             0xEB, 0x08, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00};
      auto rvaOffset = 8;
      *reinterpret_cast<PVOID *>(&rawData[rvaOffset]) = absoluteAddr;

      this->AddTranslation(
          new RelativeTranslation(rva, rawData, sizeOfRawData, rvaOffset));
    } else {
      this->AddTranslation(new RelativeTranslation(
          rva, absoluteAddr, "mov r11, 0x%p", ABSOLUTE_SIG));
      this->AddTranslation(new ModifiedTranslation(rva, "call [r11]"));
    }

    break;
  case ZYDIS_MNEMONIC_JB:
  case ZYDIS_MNEMONIC_JBE:
  case ZYDIS_MNEMONIC_JCXZ:
  case ZYDIS_MNEMONIC_JECXZ:
  case ZYDIS_MNEMONIC_JKNZD:
  case ZYDIS_MNEMONIC_JKZD:
  case ZYDIS_MNEMONIC_JL:
  case ZYDIS_MNEMONIC_JLE:
  case ZYDIS_MNEMONIC_JNB:
  case ZYDIS_MNEMONIC_JNBE:
  case ZYDIS_MNEMONIC_JNL:
  case ZYDIS_MNEMONIC_JNLE:
  case ZYDIS_MNEMONIC_JNO:
  case ZYDIS_MNEMONIC_JNP:
  case ZYDIS_MNEMONIC_JNS:
  case ZYDIS_MNEMONIC_JNZ:
  case ZYDIS_MNEMONIC_JO:
  case ZYDIS_MNEMONIC_JP:
  case ZYDIS_MNEMONIC_JRCXZ:
  case ZYDIS_MNEMONIC_JS:
  case ZYDIS_MNEMONIC_JZ: {
    // Convert JCC to absolute

    PBYTE rawData = nullptr;
    PBYTE buffer = nullptr;
    auto sizeOfRawData = 2 + 14;

    if (instruction.length > 3) {
      if (*instruction_buffer == 0xF2 || *instruction_buffer == 0xF3) {
        sizeOfRawData += 3;
        buffer = rawData = new BYTE[sizeOfRawData];
        *buffer = *instruction_buffer;

        ++instruction_buffer;
        ++buffer;
      } else {
        sizeOfRawData += 2;
        buffer = rawData = new BYTE[sizeOfRawData];
      }

      if (*instruction_buffer != 0x0F) {
        errorf("found malformed relative long jump (%p)\n", rva.Start());
        throw TranslatorException();
      }

      ++instruction_buffer;

      *buffer = *instruction_buffer - 0x10;
      ++buffer;
    } else {
      sizeOfRawData += instruction.length;
      buffer = rawData = new BYTE[sizeOfRawData];

      memcpy(buffer, instruction_buffer, instruction.length - 1);
      buffer += (instruction.length - 1);
    }

    *buffer = 0x02;
    ++buffer;

    memcpy(buffer, "\xEB\x0E\xFF\x25\x00\x00\x00\x00", 8);
    buffer += 8;

    auto rvaOffset = static_cast<DWORD>(buffer - &rawData[0]);
    *reinterpret_cast<PVOID *>(buffer) = absoluteAddr;

    this->AddBranch(absoluteAddr, rva.Start());
    this->AddTranslation(
        new RelativeTranslation(rva, rawData, sizeOfRawData, rvaOffset));

    break;
  }
  default: {
    // Standard relative instruction
    // Replace relative pointer with absolute register

    auto unusedStr =
        ZydisRegisterGetString(utils::disasm::unused_gp(instruction));

    this->AddTranslation(new ModifiedTranslation(rva, "push %s", unusedStr));
    this->AddTranslation(new RelativeTranslation(
        rva, absoluteAddr, "mov %s, 0x%p", unusedStr, ABSOLUTE_SIG));

    auto instructionStr = utils::disasm::format(instruction, rva.Start());
    instructionStr = std::regex_replace(instructionStr, std::regex("\\[.*\\]"),
                                        "[" + std::string(unusedStr) + "]");
    this->AddTranslation(
        new ModifiedTranslation(rva, "%s", instructionStr.c_str()));

    this->AddTranslation(new ModifiedTranslation(rva, "pop %s", unusedStr));

    break;
  }
  }
}

// Returns whether the register points to the base of the PE
bool Translator::IsRegisterBase(ZydisRegister reg, int translation_index,
                                int starting_index) {
  if (utils::disasm::same_register(reg, ZYDIS_REGISTER_RSP)) {
    return false;
  }

  for (auto i = translation_index; i >= starting_index; --i) {
    auto prevTrans = this->translations_[i].get();
    if (!prevTrans->Executable()) {
      continue;
    }

    if (i != translation_index) {
      auto prevInst =
          utils::disasm::decode(prevTrans->Buffer(), prevTrans->BufferSize());
      if (prevInst.mnemonic == ZYDIS_MNEMONIC_INT3 ||
          prevInst.mnemonic == ZYDIS_MNEMONIC_INVALID) {
        return false;
      }

      auto relativeTrans = dynamic_cast<RelativeTranslation *>(prevTrans);
      auto prevInstOperands = utils::disasm::operands(prevInst);
      switch (prevInstOperands.size()) {
      case 1:
        if (prevInstOperands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            utils::disasm::same_register(prevInstOperands[0].reg.value, reg)) {
          return false;
        }

        break;
      case 2:
        if (prevInstOperands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            utils::disasm::same_register(prevInstOperands[0].reg.value, reg)) {
          return relativeTrans && relativeTrans->Pointer() == nullptr;
        }

        break;
      }
    }

    this->TraceBranch(i, starting_index);
  }

  return false;
}

// Fixes scaled-index-byte mode instructions that are relative the base of the
// PE
void Translator::FixSIB(int translation_index, int starting_index) {
  auto trans = dynamic_cast<DefaultTranslation *>(
      this->translations_[translation_index].get());
  if (!trans) {
    return;
  }

  auto rva = trans->RVA();
  auto inst = utils::disasm::decode(trans->Buffer(), trans->BufferSize());
  auto operands = utils::disasm::operands(inst);
  if (operands.size() != 2) {
    return;
  }

  ZydisDecodedOperand sibOperand = {0};
  for (auto &op : operands) {
    if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.disp.has_displacement &&
        op.mem.disp.value > 0) {
      sibOperand = op;
      break;
    }
  }

  if (sibOperand.type == ZYDIS_OPERAND_TYPE_UNUSED) {
    return;
  }

  if (this->IsRegisterBase(sibOperand.mem.base, translation_index,
                           starting_index)) {
    auto unusedStr = ZydisRegisterGetString(utils::disasm::unused_gp(inst));

    // push unusedRegister
    this->ReplaceTranslation(
        translation_index++,
        new ModifiedTranslation(rva, "push %s", unusedStr));

    // mov unusedRegister, absolutePointer
    this->InsertTranslation(
        translation_index++,
        new RelativeTranslation(
            rva, reinterpret_cast<PVOID>(sibOperand.mem.disp.value),
            "mov %s, 0x%p", unusedStr, ABSOLUTE_SIG));

    auto instructionStr = utils::disasm::format(inst, rva.Start());
    instructionStr = std::regex_replace(
        instructionStr, std::regex("\\[[^\\+]*"), "[" + std::string(unusedStr));
    instructionStr =
        std::regex_replace(instructionStr, std::regex("\\+0x(.*)\\]"), "]");

    // Original instruction using absolutePointer as the base
    this->InsertTranslation(
        translation_index++,
        new ModifiedTranslation(rva, "%s", instructionStr.c_str()));

    // pop unusedRegister
    this->InsertTranslation(translation_index,
                            new ModifiedTranslation(rva, "pop %s", unusedStr));
  } else if (sibOperand.mem.scale == 1 &&
             this->IsRegisterBase(sibOperand.mem.index, translation_index,
                                  starting_index)) {
    auto unusedStr = ZydisRegisterGetString(utils::disasm::unused_gp(inst));

    // push unusedRegister
    this->ReplaceTranslation(
        translation_index++,
        new ModifiedTranslation(rva, "push %s", unusedStr));

    // mov unusedRegister, absolutePointer
    this->InsertTranslation(
        translation_index++,
        new RelativeTranslation(
            rva, reinterpret_cast<PVOID>(sibOperand.mem.disp.value),
            "mov %s, 0x%p", unusedStr, ABSOLUTE_SIG));

    auto instructionStr = utils::disasm::format(inst, rva.Start());

    // Original instruction using unusedRegister as the index
    instructionStr =
        std::regex_replace(instructionStr, std::regex("\\+.*\\*1.*\\]"),
                           "+" + std::string(unusedStr) + "]");

    // Original instruction using absolutePointer as the base
    this->InsertTranslation(
        translation_index++,
        new ModifiedTranslation(rva, "%s", instructionStr.c_str()));

    // pop unusedRegister
    this->InsertTranslation(translation_index,
                            new ModifiedTranslation(rva, "pop %s", unusedStr));
  }
}

// Adds an executable code section
void Translator::AddExecuteSection(PBYTE base, PIMAGE_SECTION_HEADER section) {
  // Do an initial pass to create a code map
  auto startingSize = static_cast<INT>(this->translations_.size());
  for (auto i = 0UL; i < section->SizeOfRawData;) {
    auto instBuffer = base + section->PointerToRawData + i;
    auto inst = utils::disasm::decode(instBuffer, section->SizeOfRawData - i);

    Region rva(section->VirtualAddress + i, inst.length);
    if (inst.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
      this->AddRelativeTranslation(rva, instBuffer, inst);
    } else if (inst.mnemonic == ZYDIS_MNEMONIC_JMP &&
               this->AddSwitchTranslation(rva, instBuffer, inst)) {
      // Success
    } else {
      this->AddTranslation(
          new DefaultTranslation(rva, instBuffer, inst.length));
    }

    i += inst.length;
  }

  // Do a second pass analyzing relative SIB instructions utilizing the code map
  for (auto i = startingSize; i < this->translations_.size(); ++i) {
    this->FixSIB(i, startingSize);
  }
}
\n
} // namespace core
