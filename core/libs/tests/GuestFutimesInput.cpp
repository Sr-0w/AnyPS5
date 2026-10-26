#include "prx/libkernel/include/Api.hpp"
#include "prx/libkernel/Time/include/Time.hpp"
#include "prx/libc/include/Api.hpp"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <source_location>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

static void Require(bool value, std::source_location location = std::source_location::current()) {
    if (!value) {
        std::fprintf(stderr, "futimes input check failed at line %u (guest errno %d)\n", location.line(), *__error_nid_postfix());
        std::abort();
    }
}

using Times = std::array<KernelTimeval, 2>;

static Times ReadTimes(int descriptor) {
#ifdef _WIN32
    FILETIME access{}, modified{};
    Require(GetFileTime(reinterpret_cast<HANDLE>(::_get_osfhandle(descriptor)), nullptr, &access, &modified) != 0);
    const auto decode = [](FILETIME time) {
        const auto ticks = ((static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime) - 116444736000000000ULL;
        return KernelTimeval{static_cast<std::int64_t>(ticks / 10000000), static_cast<std::int64_t>(ticks % 10000000 / 10)};
    };
    return {decode(access), decode(modified)};
#else
    struct stat status{};
    Require(::fstat(descriptor, &status) == 0);
#ifdef __APPLE__
    return {KernelTimeval{status.st_atimespec.tv_sec, status.st_atimespec.tv_nsec / 1000},
        KernelTimeval{status.st_mtimespec.tv_sec, status.st_mtimespec.tv_nsec / 1000}};
#else
    return {KernelTimeval{status.st_atim.tv_sec, status.st_atim.tv_nsec / 1000},
        KernelTimeval{status.st_mtim.tv_sec, status.st_mtim.tv_nsec / 1000}};
#endif
#endif
}

static void RequireTimes(int descriptor, const Times& expected) {
    const auto actual = ReadTimes(descriptor);
    for (std::size_t i = 0; i < expected.size(); ++i) {
        Require(actual[i].tv_sec == expected[i].tv_sec && actual[i].tv_usec == expected[i].tv_usec);
    }
}

class GuardedTimes {
public:
    GuardedTimes() {
#ifdef _WIN32
        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        page = info.dwPageSize;
        memory = static_cast<char*>(VirtualAlloc(nullptr, 2 * page, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        Require(memory != nullptr);
        DWORD previous = 0;
        Require(VirtualProtect(memory + page, page, PAGE_NOACCESS, &previous) != 0);
#else
        const auto size = sysconf(_SC_PAGESIZE);
        Require(size > 0);
        page = static_cast<std::size_t>(size);
        memory = static_cast<char*>(mmap(nullptr, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        Require(memory != MAP_FAILED);
        Require(mprotect(memory + page, page, PROT_NONE) == 0);
#endif
    }

    ~GuardedTimes() {
#ifdef _WIN32
        Require(VirtualFree(memory, 0, MEM_RELEASE) != 0);
#else
        Require(munmap(memory, 2 * page) == 0);
#endif
    }

    char* End() const { return memory + page; }

    void ReadOnly() {
#ifdef _WIN32
        DWORD previous = 0;
        Require(VirtualProtect(memory, page, PAGE_READONLY, &previous) != 0);
#else
        Require(mprotect(memory, page, PROT_READ) == 0);
#endif
    }

private:
    char* memory = nullptr;
    std::size_t page = 0;
};

static void Reject(int descriptor, const KernelTimeval* times, int error) {
    *__error_nid_postfix() = 77;
    Require(futimes_nid_postfix(descriptor, times) == -1 && *__error_nid_postfix() == error);
    Require(sceKernelFutimes(descriptor, times) == static_cast<int>(0x80020000u + static_cast<unsigned>(error)));
}

int main() {
    const auto close = [](std::FILE* stream) { Require(std::fclose(stream) == 0); };
    const std::unique_ptr<std::FILE, decltype(close)> file(std::tmpfile(), close);
    Require(file != nullptr);
#ifdef _WIN32
    const int descriptor = ::_fileno(file.get());
#else
    const int descriptor = ::fileno(file.get());
#endif
    Require(descriptor >= 0);
    const Times initial{KernelTimeval{1700000000, 123456}, KernelTimeval{1700000010, 654321}};
    Require(futimes_nid_postfix(descriptor, initial.data()) == 0);
    RequireTimes(descriptor, initial);
    GuardedTimes memory;
    for (const auto* times : {reinterpret_cast<const KernelTimeval*>(1),
             reinterpret_cast<const KernelTimeval*>(memory.End()),
             reinterpret_cast<const KernelTimeval*>(UINTPTR_MAX - sizeof(Times) / 2)}) {
        Reject(descriptor, times, 14);
        RequireTimes(descriptor, initial);
        Reject(-1, times, 14);
    }
    Times invalid = initial;
    invalid[0].tv_usec = -1;
    for (const std::size_t readable : {std::size_t{1}, sizeof(KernelTimeval), sizeof(Times) - 1}) {
        auto* prefix = memory.End() - readable;
        std::memcpy(prefix, invalid.data(), readable);
        Reject(descriptor, reinterpret_cast<const KernelTimeval*>(prefix), 14);
        RequireTimes(descriptor, initial);
        Reject(-1, reinterpret_cast<const KernelTimeval*>(prefix), 14);
    }
    for (std::size_t i = 0; i < initial.size(); ++i) {
        for (const std::int64_t microseconds : {-1LL, 1000000LL}) {
            invalid = initial;
            invalid[i].tv_usec = microseconds;
            Reject(descriptor, invalid.data(), 22);
            RequireTimes(descriptor, initial);
            Reject(-1, invalid.data(), 22);
        }
    }
    Reject(-1, initial.data(), 9);
    const int socket = socket_nid_postfix(2, 1, 0);
    Require(socket >= 0);
    Reject(socket, reinterpret_cast<const KernelTimeval*>(memory.End()), 14);
    Reject(socket, initial.data(), 22);
    Require(close_nid_postfix(socket) == 0);
    RequireTimes(descriptor, initial);
    const Times replacement{KernelTimeval{1710000000, 234567}, KernelTimeval{1710000010, 765432}};
    auto* boundary = memory.End() - sizeof(replacement);
    std::memcpy(boundary, replacement.data(), sizeof(replacement));
    memory.ReadOnly();
    const auto* times = reinterpret_cast<const KernelTimeval*>(boundary);
    Require(futimes_nid_postfix(descriptor, times) == 0);
    RequireTimes(descriptor, replacement);
    Require(sceKernelFutimes(descriptor, times) == 0);
    RequireTimes(descriptor, replacement);
    Require(std::memcmp(boundary, replacement.data(), sizeof(replacement)) == 0);
    Require(futimes_nid_postfix(descriptor, nullptr) == 0);
    const auto now = ReadTimes(descriptor);
    Require(now[0].tv_sec > replacement[0].tv_sec && now[1].tv_sec > replacement[1].tv_sec);
}
