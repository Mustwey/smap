#include "core/translation/translation.h"
#include "core/translator/translator.h"
#include "core/align/align.h"
#include <vector>
#include <cstring>

namespace core {

static void ResetMappedRegion(Translator& tr, Translation& tl) {
    DWORD sz = tl.BufferSize();
    if(!sz) return;
    PBYTE mapped = tl.Mapped();
    if(!mapped) return;

    if(tl.FreeOnFail()) {
        VirtualFreeEx(tr.Process(), mapped, 0, MEM_RELEASE);
    } else {
        std::vector<BYTE> pad(sz, core::align::kAlignmentByte);
        WriteProcessMemory(tr.Process(), mapped, pad.data(), sz, nullptr);
    }
    tl.Mapped(nullptr);
}

void DefaultTranslation::Fail(Translator& t)  { ResetMappedRegion(t,*this);} 
void RegionTranslation::Fail(Translator& t)   { ResetMappedRegion(t,*this);} 
void ModifiedTranslation::Fail(Translator& t) { ResetMappedRegion(t,*this);} 

bool RelativeTranslation::Resolve(Translator& t) {
    Pointer() = t.Translate(Pointer());
    return Pointer()!=nullptr;
}
void RelativeTranslation::Fail(Translator& t) { ResetMappedRegion(t,*this);} 

bool SwitchTranslation::Resolve(Translator& t) {
    for(auto& r:JumpTable) {
        r = t.Translate(r);
        if(!r) return false;
    }
    return WriteProcessMemory(t.Process(), MappedJumpTable, JumpTable.data(), static_cast<DWORD>(JumpTable.size()*sizeof(PVOID)), nullptr) != 0;
}

void SwitchTranslation::Fail(Translator& t) {
    if(MappedJumpTable)       { VirtualFreeEx(t.Process(), MappedJumpTable, 0, MEM_RELEASE); MappedJumpTable=nullptr; }
    if(MappedIndirectTable)   { VirtualFreeEx(t.Process(), MappedIndirectTable, 0, MEM_RELEASE); MappedIndirectTable=nullptr; }
    ResetMappedRegion(t,*this);
}

} // namespace core 