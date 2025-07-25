#pragma once

#include <Windows.h>
#include <Zydis/Zydis.h>
#include <map>
#include <memory>
#include <vector>

#include "core/region/region.h"
#include "core/translation/translation.h"
#include "utils/log.h"
#include "utils/assemble.h"
#include "utils/disasm.h"
#include "utils/pe.h"
#include "utils/process.h"
#include "utils/signature.h"

namespace core {

class Translator {
private:
    HANDLE                                        process_handle_ = nullptr;
    PBYTE                                         image_base_     = nullptr;
    PIMAGE_NT_HEADERS                             nt_headers_     = nullptr;

    std::vector<std::unique_ptr<Translation>>     translations_;
    std::map<void*, void*>                        branches_;   // dest -> src

    // helpers ---------------------------------------------------------------
    bool  MapHeaders();
    void  AddSection(PBYTE base, PIMAGE_SECTION_HEADER sec);
    void  AddExecuteSection(PBYTE base, PIMAGE_SECTION_HEADER sec);

    void  AddRelativeTranslation(Region rva, PBYTE buf, const ZydisDecodedInstruction& inst);
    bool  AddSwitchTranslation(Region rva, PBYTE buf, const ZydisDecodedInstruction& inst);
    Translation* AlignExport(std::size_t& idx, std::size_t total,
                             const std::vector<Region>& regions,
                             std::size_t region_begin, std::size_t region_end);

    std::vector<void*> GetExports();
    bool  ResolveImports();
    bool  ResolveRelocations();
    void  FixSIB(int index, int start_index);

    // small container helpers ----------------------------------------------
    inline void AddTranslation(Translation* t) { translations_.emplace_back(t); }
    inline void InsertTranslation(size_t i, Translation* t) { translations_.insert(translations_.begin() + i, std::unique_ptr<Translation>(t)); }
    inline void ReplaceTranslation(size_t i, Translation* t) { translations_[i].reset(t); }
    inline void RemoveTranslation(size_t i) { translations_.erase(translations_.begin() + i); }
    inline void AddBranch(void* dest, void* src) { branches_.emplace(dest, src); }

public:
    bool Initialize(HANDLE process, PBYTE base);
    bool Align(const std::vector<Region>& regions, DWORD scatter_threshold = 1);
    bool Resolve();
    bool Map(void*& entry);
    void Fail();

    // translation helpers ---------------------------------------------------
    void* Translate(void* rva) const;
    template<typename T> T Translate(T rva) const { return reinterpret_cast<T>(Translate(reinterpret_cast<void*>(rva))); }

    void* TranslateRaw(void* rva) const;
    template<typename T> T TranslateRaw(T rva) const { return reinterpret_cast<T>(TranslateRaw(reinterpret_cast<void*>(rva))); }

    IMAGE_SECTION_HEADER* TranslateRawSection(void* rva) const;

    HANDLE Process() const noexcept { return process_handle_; }
};

} // namespace core
