#pragma once

#include <Windows.h>
#include <Zydis/Zydis.h>

#include <map>
#include <memory>
#include <vector>

#include "core/region/region.h"
#include "core/translation/translation.h"
#include "utils/log.h"

namespace core {

class Translator {
 private:
  HANDLE ProcessHandle = nullptr;
  PBYTE ImageBase = nullptr;
  PIMAGE_NT_HEADERS NtHeaders = nullptr;
  std::vector<std::unique_ptr<Translation>> Translations;
  std::map<void*, void*> Branches;

  bool MapHeaders();
  std::vector<void*> GetExports();
  bool ResolveImports();
  bool ResolveRelocations();
  Translation* AlignExport(size_t& translationIndex, size_t translationsCount,
                           std::vector<Region>& regions, size_t regionStart,
                           size_t regionEnd);
  void TraceBranch(int& translationIndex, int startingIndex);
  bool IsRegisterAbsolute(ZydisRegister reg, int translationIndex,
                          int startingIndex, void*& absolute);
  bool AddSwitchTranslation(Region& rva, PBYTE jumpBuffer,
                            ZydisDecodedInstruction& jumpInstruction);
  void AddRelativeTranslation(Region& rva, PBYTE instructionBuffer,
                              ZydisDecodedInstruction& instruction);
  bool IsRegisterBase(ZydisRegister reg, int translationIndex,
                      int startingIndex);
  void FixSIB(int translationIndex, int startingIndex);
  void AddSection(PBYTE base, PIMAGE_SECTION_HEADER section);
  void AddExecuteSection(PBYTE base, PIMAGE_SECTION_HEADER section);

  inline void RemoveTranslation(size_t idx) {
    Translations.erase(Translations.begin() + idx);
  }
  inline void AddTranslation(Translation* t) {
    Translations.push_back(std::unique_ptr<Translation>(t));
  }
  inline void InsertTranslation(size_t idx, Translation* t) {
    Translations.insert(Translations.begin() + idx,
                        std::unique_ptr<Translation>(t));
  }
  inline void ReplaceTranslation(size_t idx, Translation* t) {
    Translations[idx] = std::unique_ptr<Translation>(t);
  }
  inline void AddBranch(void* dest, void* src) {
    if (!Branches.count(dest)) Branches[dest] = src;
  }

 public:
  bool Initialize(HANDLE process, PBYTE base);
  bool Align(std::vector<Region>& regions, DWORD scatterThreshold = 1);
  bool Resolve();
  bool Map(void*& entry);

  void* Translate(void* rva);
  template <typename T>
  T Translate(T rva) {
    return reinterpret_cast<T>(Translate(reinterpret_cast<void*>(rva)));
  }

  void* TranslateRaw(void* rva);
  template <typename T>
  T TranslateRaw(T rva) {
    return reinterpret_cast<T>(TranslateRaw(reinterpret_cast<void*>(rva)));
  }
  IMAGE_SECTION_HEADER* TranslateRawSection(void* rva);

  HANDLE Process() const noexcept { return ProcessHandle; }
  void Fail();
};

}  // namespace core
