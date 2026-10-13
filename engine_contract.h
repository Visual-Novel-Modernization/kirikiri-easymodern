#pragma once
#include <stdint.h>
#include <string.h>
#include "jxl_decode.h"

// Verified against the exact supported executable, not inferred from a title.
// PNG registry: RVA 0xE9F09; dispatcher call/add esp,0x20: RVA 0xEC4AB.
// Read thunk: RVA 0x12393A, vtable slot 1, explicit stack self, caller cleanup.
using StreamSeek = uint64_t (__cdecl *)(void*, int64_t, int32_t);
using StreamRead = uint32_t (__cdecl *)(void*, void*, uint32_t);
using SizeCallback = void (__cdecl *)(void*, uint32_t, uint32_t);
using ScanlineCallback = void* (__cdecl *)(void*, int32_t);
using MetaCallback = void (__cdecl *)(void*, const void*, const void*);
using PngHandler = void (__cdecl *)(void*, void*, SizeCallback, ScanlineCallback,
                                   MetaCallback, void*, int32_t, int32_t);
constexpr uintptr_t kPngHandlerRva = 0x00123B10;
constexpr uint8_t kPngPrologue[] = {0x55,0x8b,0xec,0x6a,0xff};
constexpr char kExpectedExeSha256[] = "9b7733355d5b717d38a45c32148041f0e08462a0ca11844854fbec15dbad6b93";

inline bool SubmitJxlBgra(const JxlDecodedImage& image, void* opaque,
                         SizeCallback size, ScanlineCallback scanline) {
  if (!size || !scanline || !image.width || !image.height ||
      image.bgra.size() != (uint64_t)image.width * image.height * 4) return false;
  size(opaque, image.width, image.height);
  for (uint32_t y = 0; y < image.height; ++y) {
    void* row = scanline(opaque, (int32_t)y);
    if (!row) return false;
    memcpy(row, image.bgra.data() + (size_t)y * image.width * 4, (size_t)image.width * 4);
    scanline(opaque, -1);
  }
  return true;
}

inline bool PeekJxlStream(void* stream) {
  if (!stream || !*(void***)stream) return false;
  void** table = *(void***)stream;
  auto seek = (StreamSeek)table[0]; auto read = (StreamRead)table[1];
  uint64_t pos = seek(stream, 0, 1);
  if (pos > INT64_MAX) return false;
  uint8_t header[12] = {};
  uint32_t got = read(stream, header, sizeof(header));
  return seek(stream, (int64_t)pos, 0) == pos && got <= sizeof(header) && IsJxlPayload(header, got);
}

inline bool ReadWholeStream(void* stream, std::vector<uint8_t>* bytes) {
  if (!stream || !bytes || !*(void***)stream) return false;
  void** table = *(void***)stream;
  auto seek = (StreamSeek)table[0]; auto read = (StreamRead)table[1];
  uint64_t pos = seek(stream, 0, 1), end = seek(stream, 0, 2);
  if (pos > INT64_MAX || seek(stream, (int64_t)pos, 0) != pos ||
      end < pos || end-pos < 2 || end-pos > 512ULL*1024*1024) return false;
  bool ok = true;
  try {
    bytes->resize((size_t)(end-pos));
    size_t at = 0;
    while (at < bytes->size()) {
      uint32_t requested = (uint32_t)(bytes->size()-at);
      uint32_t got = read(stream, bytes->data()+at, requested);
      if (!got || got > requested) { ok = false; break; }
      at += got;
    }
  } catch (...) { ok = false; }
  bool restored = seek(stream, (int64_t)pos, 0) == pos;
  return ok && restored;
}
