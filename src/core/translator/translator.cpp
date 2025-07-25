#include "core/translator/translator.h"
#include <algorithm>
#include <regex>
#include <cstring>

#include "core/translation/translation.h"
#include "utils/assemble.h"
#include "utils/disasm.h"
#include "utils/pe.h"
#include "utils/process.h"
#include "core/align/align.h"

using core::Region;
namespace core {

bool Translator::Initialize(HANDLE process, PBYTE base) {
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE){ errorf("invalid DOS signature\n"); return false; }
    auto nt  = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE){ errorf("invalid NT signature\n"); return false; }

    ProcessHandle = process;
    ImageBase     = base;
    NtHeaders     = nt;

    if(!MapHeaders()) return false;

    auto sec = IMAGE_FIRST_SECTION(nt);
    for(int i=0;i<nt->FileHeader.NumberOfSections;++i,++sec) AddSection(base,sec);

    return true;
}

bool Translator::MapHeaders() {
    DWORD sz = NtHeaders->OptionalHeader.SizeOfHeaders;
    PBYTE remote = static_cast<PBYTE>(VirtualAllocEx(ProcessHandle,nullptr,sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if(!remote){ errorf("failed to alloc headers\n"); return false; }
    Translations.emplace_back(std::make_unique<RegionTranslation>(Region(0ULL,sz),remote,ImageBase,sz));
    return true;
}

std::vector<void*> Translator::GetExports() {
    std::vector<void*> out;
    auto& dir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if(!dir.VirtualAddress) return out;
    auto ed = TranslateRaw<PIMAGE_EXPORT_DIRECTORY>(dir.VirtualAddress);
    if(!ed) return out;
    auto funcs    = TranslateRaw<PULONG>(ed->AddressOfFunctions);
    auto ordinals = TranslateRaw<PUSHORT>(ed->AddressOfNameOrdinals);
    if(!funcs||!ordinals) return out;
    for(DWORD i=0;i<ed->NumberOfNames;++i) out.push_back(reinterpret_cast<void*>(static_cast<UINT_PTR>(funcs[ordinals[i]])));
    return out;
}

bool Translator::ResolveImports() {
    auto& dir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(!dir.VirtualAddress) return true;
    auto desc = TranslateRaw<PIMAGE_IMPORT_DESCRIPTOR>(dir.VirtualAddress);
    if(!desc) return true;
    for(; desc->FirstThunk; ++desc) {
        auto modName = TranslateRaw<PCHAR>(desc->Name);
        if(!modName) break;
        HMODULE local = LoadLibraryA(modName);
        if(!local){ errorf("failed to load %s\n",modName); return false; }
        auto remoteMod = utils::process::get_module(ProcessHandle,std::wstring(modName,modName+strlen(modName)));
        if(!remoteMod){ errorf("target missing %s\n",modName); return false; }
        auto thunk = TranslateRaw<PIMAGE_THUNK_DATA>(desc->FirstThunk);
        for(; thunk->u1.AddressOfData; ++thunk){
            auto ibn = TranslateRaw<PIMAGE_IMPORT_BY_NAME>(thunk->u1.AddressOfData);
            void* loc = GetProcAddress(local,ibn->Name);
            thunk->u1.Function = reinterpret_cast<UINT_PTR>(remoteMod->modBaseAddr) + (reinterpret_cast<PBYTE>(loc)-reinterpret_cast<PBYTE>(local));
        }
    }
    return true;
}

bool Translator::ResolveRelocations() {
    auto& dir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if(!dir.VirtualAddress) return true;
    auto reloc = TranslateRaw<PIMAGE_BASE_RELOCATION>(dir.VirtualAddress);
    if(!reloc) return true;
    for(DWORD processed=0; processed<dir.Size; ){
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);
        auto data = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(reloc)+sizeof(IMAGE_BASE_RELOCATION));
        auto base = TranslateRaw<PBYTE>(reloc->VirtualAddress);
        for(DWORD i=0;i<count;++i){ WORD entry=data[i]; WORD type=entry>>12; WORD off=entry&0xFFF; if(type==IMAGE_REL_BASED_DIR64){ auto& ref=*reinterpret_cast<void**>(base+off); ref = Translate(reinterpret_cast<PBYTE>(ref)-NtHeaders->OptionalHeader.ImageBase); } }
        processed += reloc->SizeOfBlock; reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PBYTE>(reloc)+reloc->SizeOfBlock);
    }
    return true;
}

void Translator::AddSection(PBYTE base, PIMAGE_SECTION_HEADER sec) {
    if(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) { AddExecuteSection(base,sec); return; }
    PBYTE remote = static_cast<PBYTE>(VirtualAllocEx(ProcessHandle,nullptr,sec->Misc.VirtualSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if(!remote) { errorf("alloc fail for section\n"); throw TranslatorException(); }
    Translations.emplace_back(std::make_unique<RegionTranslation>(Region(sec->VirtualAddress,sec->Misc.VirtualSize),remote,base+sec->PointerToRawData,std::min(sec->Misc.VirtualSize,sec->SizeOfRawData)));
}

void Translator::AddExecuteSection(PBYTE base, PIMAGE_SECTION_HEADER sec) {
    for(DWORD i=0;i<sec->SizeOfRawData;){
        PBYTE buf = base + sec->PointerToRawData + i;
        auto instOpt = utils::disasm::decode(buf, sec->SizeOfRawData-i);
        if(!instOpt) break;
        auto& inst = *instOpt;
        Region r(sec->VirtualAddress+i, inst.length);
        Translations.emplace_back(std::make_unique<DefaultTranslation>(r, buf, inst.length));
        i += inst.length;
    }
}

bool Translator::Align(std::vector<Region>& regions, DWORD) {
    size_t idx=0;
    for(auto& t:Translations){ if(!t->Executable()) continue; if(idx>=regions.size()){ PBYTE mem = static_cast<PBYTE>(VirtualAllocEx(ProcessHandle,nullptr,t->BufferSize(),MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READ)); if(!mem) return false; t->Mapped(mem,true);} else { t->Mapped(regions[idx].Start()); regions[idx].Size(t->BufferSize()); ++idx; } }
    return true;
}

bool Translator::Resolve() { return ResolveImports() && ResolveRelocations(); }

bool Translator::Map(void*& entry) {
    for(auto& t:Translations){ if(!t->BufferSize()) continue; DWORD old=0; VirtualProtectEx(ProcessHandle,t->Mapped(),t->BufferSize(),PAGE_EXECUTE_READWRITE,&old); WriteProcessMemory(ProcessHandle,t->Mapped(),t->Buffer(),t->BufferSize(),nullptr); VirtualProtectEx(ProcessHandle,t->Mapped(),t->BufferSize(),old,&old); }
    entry = Translate(NtHeaders->OptionalHeader.AddressOfEntryPoint);
    return entry!=nullptr;
}

void* Translator::TranslateRaw(void* rva) {
    auto sec = TranslateRawSection(rva);
    if(!sec) return nullptr;
    return ImageBase + sec->PointerToRawData + (reinterpret_cast<PBYTE>(rva)-reinterpret_cast<PBYTE>(static_cast<UINT_PTR>(sec->VirtualAddress)));
}

IMAGE_SECTION_HEADER* Translator::TranslateRawSection(void* rva) {
    auto sec = IMAGE_FIRST_SECTION(NtHeaders);
    for(int i=0;i<NtHeaders->FileHeader.NumberOfSections;++i,++sec){ if(Region(sec->VirtualAddress,sec->Misc.VirtualSize).Contains(rva)) return sec; }
    return nullptr;
}

void* Translator::Translate(void* rva) {
    for(auto& t:Translations){ if(t->RVA().Contains(rva)) return t->Mapped() + (reinterpret_cast<PBYTE>(rva)-t->RVA().Start()); }
    return nullptr;
}

void Translator::Fail(){ for(auto& t:Translations) t->Fail(*this); }

} // namespace core 