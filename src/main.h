#pragma once

#include <Windows.h>

namespace app {

// Parses argv and performs the mapping / hijacking workflow.
// Returns 0 on success, non-zero on error.
int run(int argc, wchar_t* argv[]);

}  // namespace app
