#pragma once

#include <Windows.h>
#include <Zydis/Zydis.h>
#include <vector>
#include <memory>
#include <map>

#include "core/region/region.h"
#include "core/translation/translation.h"
#include "utils/log.h"

namespace core {

class Translator {
public:
    bool Initialize(HANDLE process, PBYTE imageBase);
    bool Align(std::vector<Region>& regions, DWORD scatterThreshold = 1);
    bool Resolve();
    bool Map(void*& entry);
    void Fail();

    void* Translate(void* rva);
    template<typename T> T Translate(T rva) { return reinterpret_cast<T>(Translate(reinterpret_cast<void*>(rva))); }
    void* TranslateRaw(void* rva);
    template<typename T> T TranslateRaw(T rva) { return reinterpret_cast<T>(TranslateRaw(reinterpret_cast<void*>(rva))); }
    IMAGE_SECTION_HEADER* TranslateRawSection(void* rva);

    HANDLE Process() const noexcept { return ProcessHandle; }

private:
    // helpers
    bool MapHeaders();
    std::vector<void*> GetExports();
    bool ResolveImports();
    bool ResolveRelocations();
    void AddSection(PBYTE base, PIMAGE_SECTION_HEADER sec);
    void AddExecuteSection(PBYTE base, PIMAGE_SECTION_HEADER sec);

    HANDLE ProcessHandle = nullptr;
    PBYTE  ImageBase     = nullptr;
    PIMAGE_NT_HEADERS NtHeaders = nullptr;

    std::vector<std::unique_ptr<Translation>> Translations;
    std::map<void*,void*> Branches;
};

} // namespace core 