#pragma once

#include <Windows.h>
#include <memory>
#include <vector>
#include <optional>
#include <string>

#include "core/region/region.h"
#include "utils/assemble.h"
#include "utils/signature.h"
#include "utils/log.h"

#define TranslatorException() (1)
constexpr PVOID ABSOLUTE_SIG = reinterpret_cast<PVOID>(utils::sig::kAbsoluteSentinel);

namespace core {

class Translation {
private:
    Region VirtualAddress;
    PBYTE  MappedAddress   = nullptr;
    bool   FreeMappedOnFail = false;

public:
    Region RVA()        const noexcept { return VirtualAddress; }
    void   RVA(Region r)      noexcept { VirtualAddress = r; }

    PBYTE  Mapped()     const noexcept { return MappedAddress; }
    void   Mapped(PVOID p, bool free_on_fail=false) noexcept {
        MappedAddress   = reinterpret_cast<PBYTE>(p);
        FreeMappedOnFail = free_on_fail;
    }

    bool FreeOnFail() const noexcept { return FreeMappedOnFail; }

    virtual PVOID  Buffer()      noexcept = 0;
    virtual DWORD  BufferSize()  const noexcept = 0;
    virtual bool   Executable()  const noexcept = 0;
    virtual bool   Resolve(Translator& t) = 0;
    virtual void   Fail(Translator& t)    = 0;

    virtual ~Translation() = default;
};

// -----------------------------------------------------------------------------
class DefaultTranslation final : public Translation {
    PBYTE BufferPtr;
    DWORD Size;
public:
    DefaultTranslation(Region r, PVOID buf, DWORD size) noexcept : BufferPtr(reinterpret_cast<PBYTE>(buf)), Size(size) { RVA(r);}    
    PVOID Buffer()      noexcept override { return BufferPtr; }
    DWORD BufferSize()  const noexcept override { return Size; }
    bool  Executable()  const noexcept override { return true; }
    bool  Resolve(Translator&) override { return true; }
    void  Fail(Translator& t) override;
};

// -----------------------------------------------------------------------------
class RegionTranslation final : public Translation {
    PBYTE BufferPtr;
    DWORD Size;
public:
    RegionTranslation(Region r, PVOID mapped, PVOID buf, DWORD size) noexcept : BufferPtr(reinterpret_cast<PBYTE>(buf)), Size(size) {
        RVA(r);
        Mapped(mapped, true);
    }
    PVOID Buffer()      noexcept override { return BufferPtr; }
    DWORD BufferSize()  const noexcept override { return Size; }
    bool  Executable()  const noexcept override { return false; }
    bool  Resolve(Translator&) override { return true; }
    void  Fail(Translator& t) override;
};

// -----------------------------------------------------------------------------
class ModifiedTranslation final : public Translation {
    std::unique_ptr<BYTE[]> Data;
    DWORD Size;
public:
    ModifiedTranslation(Region r, PVOID buf, DWORD size) noexcept : Data(reinterpret_cast<PBYTE>(buf)), Size(size) { RVA(r);}    
    template<typename... Args>
    ModifiedTranslation(Region r, const char* fmt, Args... args) {
        std::optional<std::vector<uint8_t>> code = utils::assemble::assemble_fmt(fmt, args...);
        if(!code) {
            errorf("assemble failed for modified translation\n");
            throw TranslatorException();
        }
        Size = static_cast<DWORD>(code->size());
        Data = std::make_unique<BYTE[]>(Size);
        memcpy(Data.get(), code->data(), Size);
        RVA(r);
    }
    PVOID Buffer()      noexcept override { return Data.get(); }
    DWORD BufferSize()  const noexcept override { return Size; }
    bool  Executable()  const noexcept override { return true; }
    bool  Resolve(Translator&) override { return true; }
    void  Fail(Translator& t) override;
};

// -----------------------------------------------------------------------------
class RelativeTranslation final : public Translation {
    std::unique_ptr<BYTE[]> Data;
    DWORD Size;
    DWORD Offset;
public:
    RelativeTranslation(Region r, PBYTE buf, DWORD size, DWORD off) noexcept : Data(buf), Size(size), Offset(off) { RVA(r);}    
    template<typename... Args>
    RelativeTranslation(Region r, PVOID absolute, const char* fmt, Args... args) {
        auto assembled = utils::assemble::assemble_fmt(fmt, args...);
        if(!assembled) {
            errorf("assemble failed for relative translation\n");
            throw TranslatorException();
        }
        auto pos = utils::sig::find_absolute(*assembled);
        if(!pos) {
            errorf("absolute sig not found in relative translation\n");
            throw TranslatorException();
        }
        Offset = static_cast<DWORD>(*pos);
        Size   = static_cast<DWORD>(assembled->size());
        Data   = std::make_unique<BYTE[]>(Size);
        memcpy(Data.get(), assembled->data(), Size);
        Pointer() = absolute;
        RVA(r);
    }
    PVOID Buffer()      noexcept override { return Data.get(); }
    DWORD BufferSize()  const noexcept override { return Size; }
    PVOID& Pointer() noexcept { return *reinterpret_cast<PVOID*>(Data.get() + Offset); }
    bool  Executable()  const noexcept override { return true; }
    bool  Resolve(Translator& t) override;
    void  Fail(Translator& t) override;
};

// -----------------------------------------------------------------------------
class SwitchTranslation final : public Translation {
    PBYTE BufferPtr;
    DWORD Size;
    std::vector<PVOID> JumpTable;
    PVOID MappedJumpTable;
    PVOID MappedIndirectTable;
public:
    SwitchTranslation(Region r,
                      PBYTE buf,
                      DWORD size,
                      std::vector<PVOID> jt,
                      PVOID mapped,
                      PVOID mapped_indirect = nullptr) noexcept
        : BufferPtr(buf), Size(size), JumpTable(std::move(jt)), MappedJumpTable(mapped), MappedIndirectTable(mapped_indirect) { RVA(r);}    
    PVOID Buffer()      noexcept override { return BufferPtr; }
    DWORD BufferSize()  const noexcept override { return Size; }
    bool  Executable()  const noexcept override { return true; }
    bool  Resolve(Translator& t) override;
    void  Fail(Translator& t) override;
};

} // namespace core 