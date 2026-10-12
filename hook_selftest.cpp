#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <vector>
#include "jxl_decode.h"

#pragma comment(lib, "advapi32.lib")

static bool ReadFileBytes(const wchar_t* path, std::vector<uint8_t>* data) {
  HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  if (file == INVALID_HANDLE_VALUE) return false;
  LARGE_INTEGER size;
  bool ok = GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= 512LL * 1024 * 1024;
  if (ok) {
    data->resize((size_t)size.QuadPart);
    DWORD read = 0;
    ok = ReadFile(file, data->data(), (DWORD)data->size(), &read, NULL) && read == data->size();
  }
  CloseHandle(file);
  return ok;
}

static bool WriteFileBytes(const wchar_t* path, const std::vector<uint8_t>& data) {
  HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
  DWORD written = 0;
  bool ok = file != INVALID_HANDLE_VALUE && WriteFile(file, data.data(), (DWORD)data.size(), &written, NULL) && written == data.size();
  if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  return ok;
}

struct CallbackProbe {
  uint32_t width, height, next_y, commits;
  std::vector<uint8_t> output;
};

static void ProbeSize(void* opaque, uint32_t width, uint32_t height) {
  CallbackProbe* probe = (CallbackProbe*)opaque;
  probe->width = width; probe->height = height; probe->next_y = 0; probe->commits = 0;
  probe->output.assign((size_t)width * height * 4, 0);
}

static void* ProbeScanline(void* opaque, int32_t y) {
  CallbackProbe* probe = (CallbackProbe*)opaque;
  if (y == -1) { ++probe->commits; return NULL; }
  if (y < 0 || (uint32_t)y != probe->next_y || (uint32_t)y >= probe->height) return NULL;
  ++probe->next_y;
  return probe->output.data() + (size_t)y * probe->width * 4;
}

static void PrintSha256(const std::vector<uint8_t>& data) {
  HCRYPTPROV provider = 0; HCRYPTHASH hash = 0; BYTE digest[32]; DWORD size = sizeof(digest);
  if (CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
      CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) &&
      CryptHashData(hash, data.data(), (DWORD)data.size(), 0) &&
      CryptGetHashParam(hash, HP_HASHVAL, digest, &size, 0)) {
    for (DWORD i = 0; i < size; ++i) printf("%02x", digest[i]);
  }
  if (hash) CryptDestroyHash(hash); if (provider) CryptReleaseContext(provider, 0);
}

int wmain(int argc, wchar_t** argv) {
  if (argc != 3) { fwprintf(stderr, L"usage: hook_selftest.exe input.jxl output.bgra\n"); return 2; }
  std::vector<uint8_t> input;
  JxlDecodedImage image = {};
  if (!ReadFileBytes(argv[1], &input)) { fwprintf(stderr, L"cannot read input\n"); return 3; }
  if (!IsJxlPayload(input.data(), input.size())) { fwprintf(stderr, L"not a JXL codestream\n"); return 4; }
  if (!DecodeJxlToBgra(input.data(), input.size(), &image)) { fwprintf(stderr, L"libjxl decode failed\n"); return 5; }
  CallbackProbe probe = {};
  if (!SubmitJxlBgra(image, &probe, ProbeSize, ProbeScanline) ||
      probe.width != image.width || probe.height != image.height ||
      probe.next_y != image.height || probe.commits != image.height || probe.output != image.bgra) {
    fwprintf(stderr, L"callback ABI/write contract selftest failed\n"); return 6;
  }
  if (!WriteFileBytes(argv[2], probe.output)) { fwprintf(stderr, L"cannot write raw output\n"); return 7; }
  printf("payloadSHA256="); PrintSha256(input);
  printf(" dimensions=%ux%u rawBGRA=%llu callbacks=ok commits=%u\n", image.width, image.height,
         (unsigned long long)image.bgra.size(), probe.commits);
  return 0;
}
