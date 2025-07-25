#pragma once

#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <string_view>
#include <optional>
#include <span>
#include <memory>
#include <system_error>
#include <cstdint>

namespace utils::file {

// ============================================================================
// Types & Constants
// ============================================================================

using Path = std::filesystem::path;
using ByteSpan = std::span<const std::uint8_t>;
using ByteVector = std::vector<std::uint8_t>;
using StringView = std::string_view;

// Maximum file size to prevent OOM (1GB)
constexpr std::size_t MAX_FILE_SIZE = 1ULL * 1024 * 1024 * 1024;

// ============================================================================
// Error Handling
// ============================================================================

enum class Error {
    None = 0,
    NotFound,
    AccessDenied,
    TooLarge,
    InvalidFormat,
    IoError,
    OutOfMemory
};

struct Result {
    Error error = Error::None;
    std::error_code system_error;
    
    constexpr bool success() const noexcept { return error == Error::None; }
    constexpr operator bool() const noexcept { return success(); }
    
    static Result ok() noexcept { return Result{}; }
    static Result fail(Error e) noexcept { return Result{e}; }
    static Result fail(std::error_code ec) noexcept { 
        Result r;
        r.system_error = ec;
        r.error = Error::IoError;
        return r;
    }
};

// ============================================================================
// File Reading
// ============================================================================

// Read entire file into memory with size validation
inline std::optional<ByteVector> read(const Path& path, Result* result = nullptr) noexcept {
    try {
        std::error_code ec;
        auto size = std::filesystem::file_size(path, ec);
        if (ec) {
            if (result) *result = Result::fail(ec);
            return std::nullopt;
        }
        
        if (size > MAX_FILE_SIZE) {
            if (result) *result = Result::fail(Error::TooLarge);
            return std::nullopt;
        }
        
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            if (result) *result = Result::fail(Error::NotFound);
            return std::nullopt;
        }
        
        ByteVector buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            if (result) *result = Result::fail(Error::IoError);
            return std::nullopt;
        }
        
        if (result) *result = Result::ok();
        return buffer;
    } catch (const std::bad_alloc&) {
        if (result) *result = Result::fail(Error::OutOfMemory);
        return std::nullopt;
    } catch (...) {
        if (result) *result = Result::fail(Error::IoError);
        return std::nullopt;
    }
}

// Read file with specific size limit
inline std::optional<ByteVector> read_limited(const Path& path, 
                                            std::size_t max_size,
                                            Result* result = nullptr) noexcept {
    try {
        std::error_code ec;
        auto size = std::filesystem::file_size(path, ec);
        if (ec) {
            if (result) *result = Result::fail(ec);
            return std::nullopt;
        }
        
        if (size > max_size) {
            if (result) *result = Result::fail(Error::TooLarge);
            return std::nullopt;
        }
        
        return read(path, result);
    } catch (...) {
        if (result) *result = Result::fail(Error::IoError);
        return std::nullopt;
    }
}

// Memory-mapped file reader for large files
class MemoryMappedFile {
public:
    MemoryMappedFile() = default;
    MemoryMappedFile(const MemoryMappedFile&) = delete;
    MemoryMappedFile& operator=(const MemoryMappedFile&) = delete;
    MemoryMappedFile(MemoryMappedFile&&) noexcept = default;
    MemoryMappedFile& operator=(MemoryMappedFile&&) noexcept = default;
    
    static std::optional<MemoryMappedFile> open(const Path& path,
                                               Result* result = nullptr) noexcept;
    
    ByteSpan view() const noexcept { return data_; }
    std::size_t size() const noexcept { return data_.size(); }
    bool is_open() const noexcept { return data_.size() > 0; }
    
    void close() noexcept {
        data_ = ByteSpan{};
        #ifdef _WIN32
        if (mapping_) {
            UnmapViewOfFile(mapping_);
            mapping_ = nullptr;
        }
        if (file_handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(file_handle_);
            file_handle_ = INVALID_HANDLE_VALUE;
        }
        #else
        if (mapping_) {
            munmap(const_cast<void*>(static_cast<const void*>(data_.data())), 
                   data_.size());
            mapping_ = nullptr;
        }
        if (fd_ != -1) {
            close(fd_);
            fd_ = -1;
        }
        #endif
    }
    
    ~MemoryMappedFile() noexcept {
        close();
    }

private:
    ByteSpan data_;
    #ifdef _WIN32
    void* mapping_ = nullptr;
    HANDLE file_handle_ = INVALID_HANDLE_VALUE;
    #else
    void* mapping_ = nullptr;
    int fd_ = -1;
    #endif
};

// ============================================================================
// File Writing
// ============================================================================

// Write buffer to file atomically using rename
inline Result write(const Path& path, ByteSpan data) noexcept {
    try {
        // Create temporary file next to target
        auto temp_path = path;
        temp_path += ".tmp";
        
        // Write to temp file
        {
            std::ofstream file(temp_path, std::ios::binary);
            if (!file) return Result::fail(Error::IoError);
            
            if (!file.write(reinterpret_cast<const char*>(data.data()), 
                          data.size())) {
                return Result::fail(Error::IoError);
            }
        }
        
        // Atomic rename
        std::error_code ec;
        std::filesystem::rename(temp_path, path, ec);
        if (ec) {
            std::filesystem::remove(temp_path, ec); // Best effort cleanup
            return Result::fail(ec);
        }
        
        return Result::ok();
    } catch (...) {
        return Result::fail(Error::IoError);
    }
}

// Write string to file
inline Result write(const Path& path, StringView data) noexcept {
    return write(path, ByteSpan{
        reinterpret_cast<const std::uint8_t*>(data.data()),
        data.size()
    });
}

// ============================================================================
// Pattern Matching
// ============================================================================

// Find binary pattern with wildcards
inline std::optional<std::size_t> find_pattern(ByteSpan data,
                                              ByteSpan pattern,
                                              ByteSpan mask) noexcept {
    if (pattern.size() != mask.size() || pattern.empty() || 
        pattern.size() > data.size()) {
        return std::nullopt;
    }
    
    for (std::size_t i = 0; i <= data.size() - pattern.size(); ++i) {
        bool found = true;
        for (std::size_t j = 0; j < pattern.size(); ++j) {
            if (mask[j] && data[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return i;
    }
    
    return std::nullopt;
}

// Find signature with wildcards (? for wildcard)
inline std::optional<std::size_t> find_signature(ByteSpan data,
                                                StringView signature) noexcept {
    // Parse signature string (e.g. "48 8B ? ? 83 FA")
    ByteVector pattern;
    ByteVector mask;
    
    std::string hex;
    for (char c : signature) {
        if (c == ' ') continue;
        if (c == '?') {
            pattern.push_back(0);
            mask.push_back(0);
            continue;
        }
        hex += c;
        if (hex.size() == 2) {
            pattern.push_back(static_cast<uint8_t>(std::stoul(hex, nullptr, 16)));
            mask.push_back(1);
            hex.clear();
        }
    }
    
    return find_pattern(data, pattern, mask);
}

// ============================================================================
// File System Operations
// ============================================================================

// Create all parent directories
inline Result create_parent_dirs(const Path& path) noexcept {
    try {
        auto parent = path.parent_path();
        if (parent.empty()) return Result::ok();
        
        std::error_code ec;
        if (!std::filesystem::create_directories(parent, ec) && ec) {
            return Result::fail(ec);
        }
        return Result::ok();
    } catch (...) {
        return Result::fail(Error::IoError);
    }
}

// Remove file if exists
inline Result remove_if_exists(const Path& path) noexcept {
    try {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        return ec ? Result::fail(ec) : Result::ok();
    } catch (...) {
        return Result::fail(Error::IoError);
    }
}

// Get canonical absolute path
inline std::optional<Path> canonical(const Path& path) noexcept {
    try {
        std::error_code ec;
        auto result = std::filesystem::canonical(path, ec);
        return ec ? std::nullopt : std::optional{result};
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace utils::file 