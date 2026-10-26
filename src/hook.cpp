#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <vector>
#include "jxl_decode.h"
#include "tlg_hybrid.h"

#pragma comment(lib, "advapi32.lib")

// Standard KiriKiri loading handler signature
typedef void (__cdecl *LoadingHandler)(void* format_data, void* callback_data,
                                      JxlSizeCallback size, JxlScanlineCallback scanline,
                                      MetaCallback meta, void* source, int32_t keyidx,
                                      int32_t mode);

// Target RVAs discovered from executable reverse engineering (すれ違う兄妹の壊れる倫理観.exe)
static const uintptr_t kPngHandlerRva = 0x001AFFE0;
static const uintptr_t kTlgHandlerRva = 0x001B1D20;
static const uintptr_t kTjsStringConstructRva = 0x0002A870;
static const uintptr_t kTjsStringDestructRva = 0x00029A80;
static const uint8_t kExpectedPrologue[5] = {0x55, 0x8b, 0xec, 0x6a, 0xff};

static volatile LONG g_installed = 0;
static volatile LONG g_active_count = 0;

static LoadingHandler g_original_png = NULL;
static LoadingHandler g_original_tlg = NULL;
static BYTE* g_trampoline_png = NULL;
static BYTE* g_trampoline_tlg = NULL;

static void* g_tjs_construct = NULL;
static void* g_tjs_destruct = NULL;

static void Log(const char* format, ...) {
  char text[512];
  va_list args;
  va_start(args, format);
  _vsnprintf(text, sizeof(text) - 1, format, args);
  va_end(args);
  text[sizeof(text) - 1] = '\0';
  OutputDebugStringA("[jxl_hook] ");
  OutputDebugStringA(text);
  OutputDebugStringA("\n");

  wchar_t directory[MAX_PATH];
  DWORD length = GetModuleFileNameW(NULL, directory, MAX_PATH);
  if (!length || length >= MAX_PATH) return;
  while (length && directory[length - 1] != L'\\' && directory[length - 1] != L'/') --length;
  if (!length || length + 14 >= MAX_PATH) return;
  lstrcpyW(directory + length, L"jxl_hook.log");
  HANDLE file = CreateFileW(directory, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file != INVALID_HANDLE_VALUE) {
    char line[560];
    int line_length = _snprintf(line, sizeof(line), "[jxl_hook] %s\r\n", text);
    DWORD written;
    if (line_length > 0) WriteFile(file, line, (DWORD)line_length, &written, NULL);
    CloseHandle(file);
  }
}

static bool ReadWholeStreamFromCurrent(void* stream, std::vector<uint8_t>* bytes, size_t max_size = 512 * 1024 * 1024) {
  if (!stream || !bytes) return false;
  uint64_t cur = GetStreamPosition(stream);
  if (!SeekStreamPosition(stream, 0, 2)) return false; // SEEK_END (2)
  uint64_t end = GetStreamPosition(stream);
  SeekStreamPosition(stream, (int64_t)cur, 0); // SEEK_SET (0)

  if (end <= cur || end - cur > max_size) return false;
  size_t count = (size_t)(end - cur);
  try {
    bytes->resize(count);
  } catch (...) {
    return false;
  }
  return ReadStreamExact(stream, bytes->data(), (uint32_t)count);
}

static void __cdecl HookPngHandler(void* format_data, void* callback_data,
                                   JxlSizeCallback size, JxlScanlineCallback scanline,
                                   MetaCallback meta, void* source, int32_t keyidx, int32_t mode) {
  InterlockedIncrement(&g_active_count);
  bool handled = false;

  if (source) {
    uint64_t start_pos = GetStreamPosition(source);
    uint8_t probe[16] = {};
    uint32_t got = 0;
    void** vtable = *(void***)source;
    if (vtable) {
      StreamRead read = (StreamRead)vtable[1];
      got = read(source, probe, sizeof(probe));
      SeekStreamPosition(source, (int64_t)start_pos, 0);
    }

    if (IsJxlPayload(probe, got)) {
      std::vector<uint8_t> payload;
      if (ReadWholeStreamFromCurrent(source, &payload)) {
        JxlDecodedImage image;
        if (DecodeJxlToBgra(payload.data(), payload.size(), &image)) {
          handled = SubmitJxlBgra(image, callback_data, size, scanline, mode);
          if (handled) {
            Log("PNG path successfully decoded JXL %ux%u (mode=%d)", image.width, image.height, mode);
          }
        }
      }
    }
    if (!handled) {
      SeekStreamPosition(source, (int64_t)start_pos, 0);
    }
  }

  if (!handled && g_original_png) {
    g_original_png(format_data, callback_data, size, scanline, meta, source, keyidx, mode);
  }
  InterlockedDecrement(&g_active_count);
}

static void __cdecl HookTlgHandler(void* format_data, void* callback_data,
                                   JxlSizeCallback size, JxlScanlineCallback scanline,
                                   MetaCallback meta, void* source, int32_t keyidx, int32_t mode) {
  InterlockedIncrement(&g_active_count);
  bool handled = false;

  if (source) {
    uint64_t start_pos = GetStreamPosition(source);
    uint8_t probe[32] = {};
    uint32_t got = 0;
    void** vtable = *(void***)source;
    if (vtable) {
      StreamRead read = (StreamRead)vtable[1];
      got = read(source, probe, sizeof(probe));
      SeekStreamPosition(source, (int64_t)start_pos, 0);
    }

    // Branch 1: TLG0 Hybrid Container wrapping JXL
    if (got >= 15 && memcmp(probe, kTlg0HeaderMagic, sizeof(kTlg0HeaderMagic)) == 0) {
      uint32_t raw_data_offset = *(uint32_t*)(probe + 11);
      
      // Peek stream at offset 15 to check for JXL magic
      SeekStreamPosition(source, (int64_t)(start_pos + 15), 0);
      uint8_t jxl_probe[16] = {};
      uint32_t got_jxl = 0;
      if (vtable) {
        StreamRead read = (StreamRead)vtable[1];
        got_jxl = read(source, jxl_probe, sizeof(jxl_probe));
      }
      SeekStreamPosition(source, (int64_t)start_pos, 0);

      if (IsJxlPayload(jxl_probe, got_jxl) && raw_data_offset > 0 && raw_data_offset <= 128 * 1024 * 1024) {
        // Read raw JXL stream from offset 15
        SeekStreamPosition(source, (int64_t)(start_pos + 15), 0);
        std::vector<uint8_t> jxl_bytes(raw_data_offset);
        if (ReadStreamExact(source, jxl_bytes.data(), raw_data_offset)) {
          JxlDecodedImage image;
          if (DecodeJxlToBgra(jxl_bytes.data(), jxl_bytes.size(), &image)) {
            handled = SubmitJxlBgra(image, callback_data, size, scanline, mode);
            if (handled) {
              Log("TLG0 Hybrid container decoded JXL %ux%u (payload=%u bytes, mode=%d)", image.width, image.height, raw_data_offset, mode);
              
              // Now parse chunks starting at offset 15 + raw_data_offset
              SeekStreamPosition(source, (int64_t)(start_pos + 15 + raw_data_offset), 0);
              
              uint8_t chunk_header[8];
              while (ReadStreamExact(source, chunk_header, sizeof(chunk_header))) {
                char chunk_name[5] = {};
                memcpy(chunk_name, chunk_header, 4);
                uint32_t chunk_size = *(uint32_t*)(chunk_header + 4);
                if (chunk_size == 0 || chunk_size > 16 * 1024 * 1024) break;

                std::vector<uint8_t> chunk_body(chunk_size);
                if (!ReadStreamExact(source, chunk_body.data(), chunk_size)) break;

                if (memcmp(chunk_name, "tags", 4) == 0) {
                  std::vector<TlgTagEntry> tags;
                  if (ParseTlgTagsChunk(chunk_body.data(), chunk_body.size(), tags)) {
                    Log("Parsed %u TLG0 tags", (unsigned)tags.size());
                    DispatchTlgTagsToEngine(callback_data, meta, tags, g_tjs_construct, g_tjs_destruct);
                  }
                }
              }
            }
          }
        }
      }
    }
    // Branch 2: Bare JXL payload passed to TLG loader
    else if (IsJxlPayload(probe, got)) {
      std::vector<uint8_t> payload;
      if (ReadWholeStreamFromCurrent(source, &payload)) {
        JxlDecodedImage image;
        if (DecodeJxlToBgra(payload.data(), payload.size(), &image)) {
          handled = SubmitJxlBgra(image, callback_data, size, scanline, mode);
          if (handled) {
            Log("Bare JXL in TLG handler decoded %ux%u (mode=%d)", image.width, image.height, mode);
          }
        }
      }
    }

    if (!handled) {
      SeekStreamPosition(source, (int64_t)start_pos, 0);
    }
  }

  if (!handled && g_original_tlg) {
    g_original_tlg(format_data, callback_data, size, scanline, meta, source, keyidx, mode);
  }
  InterlockedDecrement(&g_active_count);
}

static bool InstallDetour(BYTE* target, void* hook_fn, BYTE** out_trampoline, LoadingHandler* out_original) {
  if (target[0] == 0xe9) {
    Log("Target %p already has a detour jump; skipping duplicate installation", target);
    return true;
  }
  if (memcmp(target, kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
    Log("Prologue mismatch at target %p", target);
    return false;
  }

  BYTE* trampoline = (BYTE*)VirtualAlloc(NULL, 10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!trampoline) return false;

  memcpy(trampoline, target, 5);
  trampoline[5] = 0xe9; // jmp target+5
  *(int32_t*)(trampoline + 6) = (int32_t)((target + 5) - (trampoline + 10));

  DWORD old_protect = 0;
  if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old_protect)) {
    VirtualFree(trampoline, 0, MEM_RELEASE);
    return false;
  }

  BYTE patch[5] = {0xe9}; // jmp hook_fn
  *(int32_t*)(patch + 1) = (int32_t)((BYTE*)hook_fn - (target + 5));
  memcpy(target, patch, 5);
  FlushInstructionCache(GetCurrentProcess(), target, 5);
  FlushInstructionCache(GetCurrentProcess(), trampoline, 10);
  VirtualProtect(target, 5, old_protect, &old_protect);

  *out_trampoline = trampoline;
  *out_original = (LoadingHandler)trampoline;
  return true;
}

static bool InstallAllHooks(void) {
  if (InterlockedCompareExchange(&g_installed, 1, 0) != 0) return true;

  HMODULE base = GetModuleHandleW(NULL);
  if (!base) {
    Log("Cannot obtain main module base");
    InterlockedExchange(&g_installed, 0);
    return false;
  }

  uintptr_t base_addr = (uintptr_t)base;
  BYTE* png_target = (BYTE*)(base_addr + kPngHandlerRva);
  BYTE* tlg_target = (BYTE*)(base_addr + kTlgHandlerRva);
  g_tjs_construct = (void*)(base_addr + kTjsStringConstructRva);
  g_tjs_destruct = (void*)(base_addr + kTjsStringDestructRva);

  Log("Module base=%p PNG_RVA=%08lx TLG_RVA=%08lx libjxl=%u",
      base, (unsigned long)kPngHandlerRva, (unsigned long)kTlgHandlerRva, JxlDecoderVersion());

  bool png_ok = InstallDetour(png_target, (void*)HookPngHandler, &g_trampoline_png, &g_original_png);
  bool tlg_ok = InstallDetour(tlg_target, (void*)HookTlgHandler, &g_trampoline_tlg, &g_original_tlg);

  if (!png_ok && !tlg_ok) {
    Log("Failed to install both graphic detours");
    InterlockedExchange(&g_installed, 0);
    return false;
  }

  Log("Installed graphic detours: PNG=%s TLG=%s", png_ok ? "OK" : "FAILED", tlg_ok ? "OK" : "FAILED");
  return true;
}

extern "C" __declspec(dllexport) HRESULT __stdcall V2Link(void* exporter) {
  (void)exporter;
  return InstallAllHooks() ? S_OK : E_FAIL;
}

extern "C" __declspec(dllexport) HRESULT __stdcall V2Unlink(void) {
  if (InterlockedCompareExchange(&g_installed, 1, 1) == 1) {
    Log("V2Unlink: refusing dynamic unload; process termination required");
    return E_FAIL;
  }
  return S_OK;
}

extern "C" __declspec(dllexport) uint32_t __stdcall JxlHookVersion(void) {
  return JxlDecoderVersion();
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
