#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdarg.h>
#include "engine_contract.h"

static volatile LONG installed = 0;
static BYTE* trampoline = nullptr;
static PngHandler original = nullptr;

static void Log(const char* format, ...) {
  char text[512]; va_list args; va_start(args, format);
  vsnprintf(text, sizeof(text), format, args); va_end(args);
  OutputDebugStringA("[island-jxl] "); OutputDebugStringA(text); OutputDebugStringA("\n");
  wchar_t path[MAX_PATH]; DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
  if (!n || n >= MAX_PATH) return;
  while (n && path[n-1] != L'\\' && path[n-1] != L'/') --n;
  if (!n || n + 20 >= MAX_PATH) return;
  lstrcpyW(path+n, L"island_jxl_hook.log");
  HANDLE f = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, 0, nullptr);
  if (f == INVALID_HANDLE_VALUE) return;
  char line[560]; int len = snprintf(line, sizeof(line), "[island-jxl] %s\r\n", text); DWORD written;
  if (len > 0 && len < (int)sizeof(line)) WriteFile(f, line, (DWORD)len, &written, nullptr);
  CloseHandle(f);
}

static bool HashFile(const wchar_t* path, char output[65]) {
  HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  HCRYPTPROV provider = 0; HCRYPTHASH hash = 0;
  bool ok = CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
            CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash);
  BYTE buffer[65536]; DWORD count;
  while (ok) {
    if (!ReadFile(file, buffer, sizeof(buffer), &count, nullptr)) { ok = false; break; }
    if (!count) break;
    ok = CryptHashData(hash, buffer, count, 0);
  }
  BYTE digest[32]; DWORD size = sizeof(digest);
  if (ok) ok = CryptGetHashParam(hash, HP_HASHVAL, digest, &size, 0) && size == 32;
  if (ok) { for (unsigned i=0; i<32; ++i) sprintf(output+i*2, "%02x", digest[i]); output[64]=0; }
  if (hash) CryptDestroyHash(hash); if (provider) CryptReleaseContext(provider, 0);
  CloseHandle(file); return ok;
}

static void LogPayload(const std::vector<uint8_t>& data, const JxlDecodedImage& image) {
  HCRYPTPROV provider=0; HCRYPTHASH hash=0; BYTE digest[32]; DWORD size=32; char hex[65];
  bool ok = CryptAcquireContextW(&provider,nullptr,nullptr,PROV_RSA_AES,CRYPT_VERIFYCONTEXT) &&
    CryptCreateHash(provider,CALG_SHA_256,0,0,&hash) && CryptHashData(hash,data.data(),(DWORD)data.size(),0) &&
    CryptGetHashParam(hash,HP_HASHVAL,digest,&size,0) && size==32;
  if (ok) {
    for (unsigned i=0;i<32;++i) sprintf(hex+i*2,"%02x",digest[i]); hex[64]=0;
    Log("JXL payloadSHA256=%s dimensions=%ux%u callbacks=ok",hex,image.width,image.height);
  }
  if (hash) CryptDestroyHash(hash); if (provider) CryptReleaseContext(provider,0);
}

static void __cdecl Handler(void* format, void* opaque, SizeCallback size,
  ScanlineCallback scanline, MetaCallback meta, void* stream, int32_t key, int32_t mode) {
  if (!PeekJxlStream(stream)) { original(format,opaque,size,scanline,meta,stream,key,mode); return; }
  std::vector<uint8_t> payload; JxlDecodedImage image;
  // Non-normal modes and color-key operations must retain original PNGs.
  if (mode == 0 && key == -1 && ReadWholeStream(stream,&payload) && DecodeJxlToBgra(payload.data(),payload.size(),&image)) {
    if (SubmitJxlBgra(image,opaque,size,scanline)) { LogPayload(payload,image); return; }
    Log("JXL callback rejected; image load failed");
  } else Log("JXL decode rejected mode=%d key=%d",mode,key);
  original(format,opaque,size,scanline,meta,stream,key,mode);
}

static bool Install() {
  if (InterlockedCompareExchange(&installed,1,0) != 0) return installed == 2;
  HMODULE module = GetModuleHandleW(nullptr);
  if (!module) goto fail;
  {
    auto dos = (const IMAGE_DOS_HEADER*)module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 4096) goto fail;
    auto nt = (const IMAGE_NT_HEADERS32*)((const BYTE*)module+dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
        nt->OptionalHeader.SizeOfImage < kPngHandlerRva+sizeof(kPngPrologue)) goto fail;
    wchar_t path[MAX_PATH]; char hash[65]; DWORD n=GetModuleFileNameW(module,path,MAX_PATH);
    if (!n || n>=MAX_PATH || !HashFile(path,hash) || strcmp(hash,kExpectedExeSha256)) {
      Log("refusing install: executable SHA256 mismatch or unreadable"); goto fail;
    }
    BYTE* target=(BYTE*)module+kPngHandlerRva;
    if (memcmp(target,kPngPrologue,sizeof(kPngPrologue))) {
      Log("refusing install: PNG prologue differs"); goto fail;
    }
    trampoline=(BYTE*)VirtualAlloc(nullptr,10,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (!trampoline) goto fail;
    memcpy(trampoline,target,5); trampoline[5]=0xe9;
    uint32_t jumpBack=(uint32_t)(uintptr_t)(target+5)-(uint32_t)(uintptr_t)(trampoline+10);
    memcpy(trampoline+6,&jumpBack,4);
    DWORD previous;
    if (!VirtualProtect(trampoline,10,PAGE_EXECUTE_READ,&previous)) goto fail;
    FlushInstructionCache(GetCurrentProcess(),trampoline,10);
    original=(PngHandler)trampoline;
    BYTE patch[5]={0xe9}; uint32_t jump=(uint32_t)(uintptr_t)Handler-(uint32_t)(uintptr_t)(target+5);
    memcpy(patch+1,&jump,4);
    if (!VirtualProtect(target,5,PAGE_EXECUTE_READWRITE,&previous)) goto fail;
    memcpy(target,patch,5); FlushInstructionCache(GetCurrentProcess(),target,5);
    DWORD ignored; if (!VirtualProtect(target,5,previous,&ignored)) Log("warning: could not restore target page protection");
    // Exact-build XP3 Read calls this global filter for every entry, ignoring
    // the info protection flag. Clear it only after the image detour succeeds.
    // Startup must already have been read from disk or decrypted by the original filter.
    auto filter = reinterpret_cast<PVOID volatile*>((BYTE*)module + 0x3b82c0);
    PVOID previousFilter = InterlockedExchangePointer(filter, nullptr);
    Log("cleared XP3 extraction filter RVA=003b82c0 previous=%p", previousFilter);
    InterlockedExchange(&installed,2);
    Log("installed PNG detour module=%p RVA=%08lx target=%p libjxl=%u",module,(unsigned long)kPngHandlerRva,target,JxlDecoderVersion());
    return true;
  }
fail:
  if (trampoline) VirtualFree(trampoline,0,MEM_RELEASE);
  trampoline=nullptr; original=nullptr; InterlockedExchange(&installed,0); return false;
}

// Isolated verification entry: uses the actual DLL handler with a synthetic stream.
// It cannot be called after installation and does not bypass executable validation.
static bool probeFallback = false;
static void __cdecl ProbeFallback(void*,void*,SizeCallback,ScanlineCallback,MetaCallback,void*,int32_t,int32_t) { probeFallback = true; }
extern "C" __declspec(dllexport) int __cdecl IslandJxlProbe(void* stream, void* opaque,
  SizeCallback size, ScanlineCallback scanline) {
  if (installed || original) return 0;
  original = ProbeFallback; probeFallback = false;
  Handler(nullptr,opaque,size,scanline,nullptr,stream,-1,0);
  original = nullptr;
  return probeFallback ? 0 : 1;
}
extern "C" __declspec(dllexport) unsigned __cdecl IslandJxlDecoderVersion() { return JxlDecoderVersion(); }
extern "C" __declspec(dllexport) HRESULT __stdcall V2Link(void*) { return Install() ? S_OK : E_FAIL; }
extern "C" __declspec(dllexport) HRESULT __stdcall V2Unlink() {
  if (installed) { Log("refusing dynamic unload of installed detour"); return E_FAIL; }
  return S_OK;
}
BOOL WINAPI DllMain(HINSTANCE,DWORD,LPVOID) { return TRUE; }
