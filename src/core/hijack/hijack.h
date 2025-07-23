#pragma once

#include <Windows.h>
#include <string_view>

namespace core::hijack {

// Hijacks by replacing an IAT entry with a tiny shell stub that
// ultimately jumps to `entry`.
bool ViaIAT(HANDLE process,
            void*  entry,                // remote code to execute
            const char* import_name,     // e.g. "Sleep"
            const wchar_t* module = nullptr); // nullptr ⇒ main module

// Hijacks by splicing a long-jmp at the start of a target export.
bool ViaHook(HANDLE process,
             void*  entry,                   // remote code to execute
             const wchar_t* module_name,     // e.g. L"kernel32.dll"
             const char* function_name);     // e.g. "Sleep"

}  // namespace core::hijack
