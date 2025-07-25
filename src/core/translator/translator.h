#pragma once

//
//  src/core/translator/translator.h
//  -------------------------------------------------------
//  Runtime PE “translator” – maps a raw PE image into a
//  foreign process, rewrites all relative code & data
//  references to absolute ones, and lays the resulting
//  code out in executable memory with minimal branch
//  overhead.  See translator.cpp for details.
//

#include <Windows.h>
#include <Zydis/Zydis.h>

#include <cstddef>
#include <memory>
#include <unordered_map>
#include <vector>

#include "core/region/region.h"
#include "core/translation/translation.h"
#include "utils/log.h"

// ---------------------------------------------------------------------------
// J / CALL sizes we need to synthesise
// ---------------------------------------------------------------------------
constexpr DWORD kJumpShortSize = 2;     //  EB xx
constexpr DWORD kJumpNearSize = 5;      //  E9 xx xx xx xx
constexpr DWORD kJumpAbsoluteSize = 14; //  FF25[0] [abs64]

// ---------------------------------------------------------------------------
// A tiny RAII helper for temporary protection changes
// ---------------------------------------------------------------------------
class ProtectGuard {
public:
  ProtectGuard(HANDLE proc, LPVOID addr, SIZE_T sz, DWORD new_prot) noexcept
      : process_(proc), address_(addr), size_(sz) {
    success_ =
        ::VirtualProtectEx(process_, address_, size_, new_prot, &old_protect_);
  }

  ProtectGuard(const ProtectGuard &) = delete;
  ProtectGuard &operator=(const ProtectGuard &) = delete;

  ~ProtectGuard() noexcept {
    if (success_) {
      DWORD tmp;
      ::VirtualProtectEx(process_, address_, size_, old_protect_, &tmp);
    }
  }

  [[nodiscard]] bool Success() const noexcept { return success_; }

private:
  HANDLE process_ = nullptr;
  LPVOID address_ = nullptr;
  SIZE_T size_ = 0;
  DWORD old_protect_ = 0;
  bool success_ = false;
};

// ---------------------------------------------------------------------------
// core::Translator
// ---------------------------------------------------------------------------
namespace core {

class Translator {
public:
  // ---- public top‑level workflow ----------------------------------------
  [[nodiscard]] bool Initialize(HANDLE process, PBYTE image_base);
  [[nodiscard]] bool Align(const std::vector<Region> &regions,
                           DWORD scatter_threshold = 1);
  [[nodiscard]] bool Resolve();
  [[nodiscard]] bool Map(void *&entry_point);

  // ---- address translation helpers --------------------------------------
  [[nodiscard]] void *Translate(void *rva) const;
  template <typename T> [[nodiscard]] T Translate(T rva) const {
    return reinterpret_cast<T>(Translate(reinterpret_cast<void *>(rva)));
  }

  [[nodiscard]] void *TranslateRaw(void *rva) const;
  template <typename T> [[nodiscard]] T TranslateRaw(T rva) const {
    return reinterpret_cast<T>(TranslateRaw(reinterpret_cast<void *>(rva)));
  }

  [[nodiscard]] IMAGE_SECTION_HEADER *TranslateRawSection(void *rva) const;

  [[nodiscard]] HANDLE Process() const noexcept { return process_handle_; }

  // Fail‑fast helper (throws to unwind internal construction work)
  [[noreturn]] void Fail() { throw TranslatorException(); }

private:
  // ---- phase helpers -----------------------------------------------------
  bool MapHeaders();
  std::vector<void *> GetExports();
  bool ResolveImports();
  bool ResolveRelocations();

  Translation *AlignExport(std::size_t &translation_index,
                           std::size_t translations_count,
                           const std::vector<Region> &regions,
                           std::size_t region_begin, std::size_t region_end);

  void TraceBranch(int &translation_index, int starting_index);

  bool IsRegisterAbsolute(ZydisRegister reg, int translation_index,
                          int starting_index, void *&absolute);

  bool AddSwitchTranslation(const Region &rva, const BYTE *jmp_buffer,
                            const ZydisDecodedInstruction &jmp_inst);

  void AddRelativeTranslation(const Region &rva, const BYTE *inst_buffer,
                              const ZydisDecodedInstruction &inst);

  bool IsRegisterBase(ZydisRegister reg, int translation_index,
                      int starting_index);

  void FixSIB(int translation_index, int starting_index);

  void AddSection(PBYTE image_base, PIMAGE_SECTION_HEADER sect);
  void AddExecuteSection(PBYTE image_base, PIMAGE_SECTION_HEADER sect);

  // ---- small container helpers ------------------------------------------
  void RemoveTranslation(std::size_t idx) {
    translations_.erase(translations_.begin() + idx);
  }

  void AddTranslation(Translation *t) { translations_.emplace_back(t); }

  void InsertTranslation(std::size_t idx, Translation *t) {
    translations_.insert(translations_.begin() + idx,
                         std::unique_ptr<Translation>(t));
  }

  void ReplaceTranslation(std::size_t idx, Translation *t) {
    translations_[idx].reset(t);
  }

  void AddBranch(void *dest, void *src) { branches_.try_emplace(dest, src); }

private:
  // ---- state -------------------------------------------------------------
  HANDLE process_handle_{nullptr};
  PBYTE image_base_{nullptr};
  PIMAGE_NT_HEADERS nt_headers_{nullptr};

  std::vector<std::unique_ptr<Translation>> translations_;
  std::unordered_map<void *, void *> branches_;
};

} // namespace core
