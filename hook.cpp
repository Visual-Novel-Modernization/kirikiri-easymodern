#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <vector>
#include "jxl_decode.h"

#pragma comment(lib, "advapi32.lib")

// This is intentionally written in C ABI terms: do not model tTJSBinaryStream as C++.
typedef uint64_t (__cdecl *StreamSeek)(void* self, int64_t offset, int32_t whence);
typedef uint32_t (__cdecl *StreamRead)(void* self, void* buffer, uint32_t size);
typedef void (__cdecl *SizeCallback)(void* callback_data, uint32_t width, uint32_t height);
typedef void* (__cdecl *ScanlineCallback)(void* callback_data, int32_t y);
typedef void (__cdecl *MetaCallback)(void*, const void*, const void*);
typedef void (__cdecl *PngHandler)(void* format_data, void* callback_data,
                                    SizeCallback size, ScanlineCallback scanline,
                                    MetaCallback meta, void* source, int32_t keyidx,
                                    int32_t mode);

static const uintptr_t kPngHandlerRva = 0x00123B10;
static const uint8_t kPngPrologue[5] = {0x55, 0x8b, 0xec, 0x6a, 0xff};
static const char kExpectedExeSha256[] =
    "e7ff31ba26e128b795d1526049d97b57f6a89a86b20eabce89d9aed48b240da9";

static volatile LONG g_installed = 0;
static volatile LONG g_loading = 0;
static BYTE g_saved[5];
static BYTE* g_target = NULL;
static BYTE* g_trampoline = NULL;
static PngHandler g_original = NULL;

static void Log(const char* format, ...) {
  char text[512];
  va_list args;
  va_start(args, format);
  _vsnprintf(text, sizeof(text) - 1, format, args);
  va_end(args);
  text[sizeof(text) - 1] = '\0';
  OutputDebugStringA("[akiyume-jxl] ");
  OutputDebugStringA(text);
  OutputDebugStringA("\n");
  wchar_t directory[MAX_PATH];
  DWORD length = GetModuleFileNameW(NULL, directory, MAX_PATH);
  if (!length || length >= MAX_PATH) return;
  while (length && directory[length - 1] != L'\\' && directory[length - 1] != L'/') --length;
  if (!length || length + 13 >= MAX_PATH) return;
  lstrcpyW(directory + length, L"jxl_hook.log");
  HANDLE file = CreateFileW(directory, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file != INVALID_HANDLE_VALUE) {
    char line[560];
    int line_length = _snprintf(line, sizeof(line), "[akiyume-jxl] %s\r\n", text);
    DWORD written;
    if (line_length > 0) WriteFile(file, line, (DWORD)line_length, &written, NULL);
    CloseHandle(file);
  }
}

static bool HashFileSha256(const wchar_t* path, char output[65]) {
  HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  HCRYPTPROV provider = 0;
  HCRYPTHASH hash = 0;
  BYTE digest[32];
  DWORD digest_size = sizeof(digest), read = 0;
  BYTE buffer[64 * 1024];
  bool ok = false;
  if (file == INVALID_HANDLE_VALUE) return false;
  if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
      !CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) goto done;
  while (ReadFile(file, buffer, sizeof(buffer), &read, NULL) && read) {
    if (!CryptHashData(hash, buffer, read, 0)) goto done;
  }
  if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_size, 0) || digest_size != sizeof(digest)) goto done;
  for (DWORD i = 0; i < digest_size; ++i) sprintf(output + i * 2, "%02x", digest[i]);
  output[64] = '\0';
  ok = true;
done:
  if (hash) CryptDestroyHash(hash);
  if (provider) CryptReleaseContext(provider, 0);
  CloseHandle(file);
  return ok;
}

static bool IsExpectedGame(void) {
  HMODULE main = GetModuleHandleW(NULL);
  if (!main) return false;
  // ASLR may relocate the exact supported executable; addresses are RVAs.
  const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)main;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
  const IMAGE_NT_HEADERS32* nt = (const IMAGE_NT_HEADERS32*)((const BYTE*)main + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
      nt->OptionalHeader.SizeOfImage < kPngHandlerRva + sizeof(kPngPrologue)) {
    Log("refusing install: invalid PE32 image");
    return false;
  }
  Log("main module base %p PNG handler RVA %08lx", main, (unsigned long)kPngHandlerRva);
  wchar_t path[MAX_PATH];
  char hash[65];
  if (!GetModuleFileNameW(main, path, MAX_PATH) || !HashFileSha256(path, hash)) {
    Log("refusing install: cannot hash main executable");
    return false;
  }
  if (lstrcmpiA(hash, kExpectedExeSha256) != 0) {
    Log("refusing install: executable SHA256 %s", hash);
    return false;
  }
  g_target = (BYTE*)main + kPngHandlerRva;
  if (memcmp(g_target, kPngPrologue, sizeof(kPngPrologue)) != 0) {
    Log("refusing install: PNG entry bytes changed");
    return false;
  }
  return true;
}

static bool PeekJxlStream(void* stream) {
  if (!stream) return false;
  void** vtable = *(void***)stream;
  if (!vtable) return false;
  StreamSeek seek = (StreamSeek)vtable[0];
  StreamRead read = (StreamRead)vtable[1];
  const uint64_t current = seek(stream, 0, 1);
  uint8_t header[12] = {};
  uint32_t got = read(stream, header, sizeof(header));
  bool restored = seek(stream, (int64_t)current, 0) == current;
  return restored && IsJxlPayload(header, got);
}

static bool ReadWholeStream(void* stream, std::vector<uint8_t>* bytes) {
  if (!stream || !bytes) return false;
  void** vtable = *(void***)stream;
  if (!vtable) return false;
  StreamSeek seek = (StreamSeek)vtable[0];
  StreamRead read = (StreamRead)vtable[1];
  const uint64_t current = seek(stream, 0, 1);
  const uint64_t end = seek(stream, 0, 2);
  if (seek(stream, (int64_t)current, 0) != current || end < current || end - current > 0x7fffffffU) return false;
  const size_t remaining = (size_t)(end - current);
  if (remaining < 2 || remaining > 512U * 1024U * 1024U) return false;
  try { bytes->resize(remaining); } catch (...) { seek(stream, (int64_t)current, 0); return false; }
  size_t at = 0;
  while (at < remaining) {
    uint32_t request = (uint32_t)((remaining - at) > 0x40000000U ? 0x40000000U : remaining - at);
    uint32_t got = read(stream, bytes->data() + at, request);
    if (!got || got > request) { seek(stream, (int64_t)current, 0); return false; }
    at += got;
  }
  return seek(stream, (int64_t)current, 0) == current;
}

static void LogPayload(const std::vector<uint8_t>& bytes, uint32_t width, uint32_t height) {
  HCRYPTPROV provider = 0; HCRYPTHASH hash = 0; BYTE digest[32]; DWORD size = sizeof(digest);
  char hex[65];
  bool ok = CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
            CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) &&
            CryptHashData(hash, bytes.data(), (DWORD)bytes.size(), 0) &&
            CryptGetHashParam(hash, HP_HASHVAL, digest, &size, 0);
  if (ok && size == sizeof(digest)) {
    for (DWORD i = 0; i < size; ++i) sprintf(hex + i * 2, "%02x", digest[i]);
    hex[64] = '\0';
    Log("JXL payloadSHA256=%s dimensions=%ux%u", hex, width, height);
  } else Log("JXL decoded dimensions=%ux%u", width, height);
  if (hash) CryptDestroyHash(hash); if (provider) CryptReleaseContext(provider, 0);
}

static void __cdecl JxlAwarePngHandler(void* format_data, void* callback_data,
                                        SizeCallback size, ScanlineCallback scanline,
                                        MetaCallback meta, void* source, int32_t keyidx, int32_t mode) {
  InterlockedIncrement(&g_loading);
  std::vector<uint8_t> payload;
  JxlDecodedImage image = {};
  bool jxl_accepted = false;
  // Peek first so normal PNG files retain their original stream behavior and cost.
  if (PeekJxlStream(source) && ReadWholeStream(source, &payload)) {
    // The original decoder's mode 1 palette and mode 2 grayscale/key semantics are not yet reproduced.
    if (mode != 0) {
      Log("rejecting JXL with unsupported PNG mode=%d keyidx=%d", mode, keyidx);
    } else {
    if (DecodeJxlToBgra(payload.data(), payload.size(), &image)) {
      jxl_accepted = SubmitJxlBgra(image, callback_data, size, scanline);
      if (jxl_accepted) LogPayload(payload, image.width, image.height);
      else Log("JXL scanline callback rejected decoded image");
    }
    }
  }
  if (!jxl_accepted && g_original) g_original(format_data, callback_data, size, scanline, meta, source, keyidx, mode);
  InterlockedDecrement(&g_loading);
}

static bool InstallDetour(void) {
  if (InterlockedCompareExchange(&g_installed, 1, 0) != 0) return true;
  if (!IsExpectedGame()) { InterlockedExchange(&g_installed, 0); return false; }
  g_trampoline = (BYTE*)VirtualAlloc(NULL, 10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!g_trampoline) { InterlockedExchange(&g_installed, 0); return false; }
  memcpy(g_saved, g_target, 5); memcpy(g_trampoline, g_saved, 5);
  g_trampoline[5] = 0xe9;
  *(int32_t*)(g_trampoline + 6) = (int32_t)((g_target + 5) - (g_trampoline + 10));
  BYTE patch[5] = {0xe9}; *(int32_t*)(patch + 1) = (int32_t)((BYTE*)JxlAwarePngHandler - (g_target + 5));
  g_original = (PngHandler)g_trampoline;
  DWORD old_protect = 0;
  if (!VirtualProtect(g_target, 5, PAGE_EXECUTE_READWRITE, &old_protect)) goto fail;
  memcpy(g_target, patch, 5); FlushInstructionCache(GetCurrentProcess(), g_target, 5);
  DWORD ignored; VirtualProtect(g_target, 5, old_protect, &ignored);
  Log("installed PNG detour at %p", g_target);
  return true;
fail:
  g_original = NULL; VirtualFree(g_trampoline, 0, MEM_RELEASE); g_trampoline = NULL; InterlockedExchange(&g_installed, 0); return false;
}

static bool RemoveDetour(void) {
  if (InterlockedCompareExchange(&g_installed, 1, 1) != 1) return true;
  if (InterlockedCompareExchange(&g_loading, 0, 0) != 0) {
    Log("refusing unload while decoder calls are active");
    return false;
  }
  if (InterlockedCompareExchange(&g_installed, 0, 1) != 1) return false;
  if (g_target && g_trampoline) { DWORD old_protect, ignored; if (!VirtualProtect(g_target, 5, PAGE_EXECUTE_READWRITE, &old_protect)) {
    InterlockedExchange(&g_installed, 1); return false;
  } else {
    memcpy(g_target, g_saved, 5); FlushInstructionCache(GetCurrentProcess(), g_target, 5); VirtualProtect(g_target, 5, old_protect, &ignored);
  }}
  g_original = NULL; if (g_trampoline) VirtualFree(g_trampoline, 0, MEM_RELEASE); g_trampoline = NULL;
  return true;
}

extern "C" __declspec(dllexport) HRESULT __stdcall V2Link(void* exporter) {
  (void)exporter;
  return InstallDetour() ? S_OK : E_FAIL;
}
extern "C" __declspec(dllexport) HRESULT __stdcall V2Unlink(void) {
  // Dynamic unload cannot synchronize a new handler entry against freeing its trampoline.
  if (InterlockedCompareExchange(&g_installed, 1, 1) == 1) {
    Log("refusing dynamic unload of installed detour; process termination is required");
    return E_FAIL;
  }
  return S_OK;
}

// Do not patch/free under loader lock. Process termination releases all mapping safely.
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
