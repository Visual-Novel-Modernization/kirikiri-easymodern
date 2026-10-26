#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <string>
#include <vector>

// Stream function pointer signatures matching KiriKiri tTJSBinaryStream C ABI
typedef uint64_t (__cdecl *StreamSeek)(void* self, int64_t offset, int32_t whence);
typedef uint32_t (__cdecl *StreamRead)(void* self, void* buffer, uint32_t size);
typedef void (__cdecl *MetaCallback)(void* callback_data, const void* name_tstr, const void* val_tstr);

static const uint8_t kTlg0HeaderMagic[11] = {'T', 'L', 'G', '0', '.', '0', 0, 's', 'd', 's', 0x1a};

struct Tlg0HeaderInfo {
  bool is_valid_tlg0;
  uint32_t raw_data_offset;
};

struct TlgTagEntry {
  std::string name;
  std::string value;
};

static inline bool ReadStreamExact(void* stream, void* buffer, uint32_t size) {
  if (!stream || !buffer || !size) return false;
  void** vtable = *(void***)stream;
  if (!vtable) return false;
  StreamRead read = (StreamRead)vtable[1];
  uint32_t total = 0;
  while (total < size) {
    uint32_t request = size - total;
    uint32_t got = read(stream, (uint8_t*)buffer + total, request);
    if (!got || got > request) return false;
    total += got;
  }
  return true;
}

static inline bool SeekStreamPosition(void* stream, int64_t offset, int32_t whence) {
  if (!stream) return false;
  void** vtable = *(void***)stream;
  if (!vtable) return false;
  StreamSeek seek = (StreamSeek)vtable[0];
  return seek(stream, offset, whence) != (uint64_t)-1;
}

static inline uint64_t GetStreamPosition(void* stream) {
  if (!stream) return 0;
  void** vtable = *(void***)stream;
  if (!vtable) return 0;
  StreamSeek seek = (StreamSeek)vtable[0];
  return seek(stream, 0, 1); // 1 = SEEK_CUR
}

static inline bool ParseTlgTagsChunk(const uint8_t* data, size_t size, std::vector<TlgTagEntry>& out_tags) {
  out_tags.clear();
  if (!data || !size) return false;
  const uint8_t* p = data;
  const uint8_t* end = data + size;

  while (p < end) {
    size_t name_len = 0;
    while (p < end && *p >= '0' && *p <= '9') {
      name_len = name_len * 10 + (*p - '0');
      p++;
    }
    if (p >= end || *p != ':') break;
    p++; // skip ':'

    if (p + name_len > end) break;
    std::string name((const char*)p, name_len);
    p += name_len;

    if (p >= end || *p != '=') break;
    p++; // skip '='

    size_t val_len = 0;
    while (p < end && *p >= '0' && *p <= '9') {
      val_len = val_len * 10 + (*p - '0');
      p++;
    }
    if (p >= end || *p != ':') break;
    p++; // skip ':'

    if (p + val_len > end) break;
    std::string val((const char*)p, val_len);
    p += val_len;

    if (p < end && *p == ',') {
      p++;
    }

    out_tags.push_back({name, val});
  }
  return !out_tags.empty();
}

static inline void DispatchTlgTagsToEngine(void* callback_data, MetaCallback meta,
                                          const std::vector<TlgTagEntry>& tags,
                                          void* fn_construct_addr,
                                          void* fn_destruct_addr) {
  if (!callback_data || !meta || !fn_construct_addr || !fn_destruct_addr) return;
  for (const auto& tag : tags) {
    uintptr_t tjs_name = 0;
    uintptr_t tjs_val = 0;
    
    const char* p_name = tag.name.c_str();
    const char* p_val = tag.value.c_str();

    __asm__ __volatile__(
        "pushl %1\n\t"
        "movl %0, %%ecx\n\t"
        "call *%2\n\t"
        :
        : "r"(&tjs_name), "r"(p_name), "r"(fn_construct_addr)
        : "eax", "ecx", "edx", "memory"
    );

    __asm__ __volatile__(
        "pushl %1\n\t"
        "movl %0, %%ecx\n\t"
        "call *%2\n\t"
        :
        : "r"(&tjs_val), "r"(p_val), "r"(fn_construct_addr)
        : "eax", "ecx", "edx", "memory"
    );

    meta(callback_data, &tjs_name, &tjs_val);

    __asm__ __volatile__(
        "movl %0, %%ecx\n\t"
        "call *%1\n\t"
        :
        : "r"(&tjs_val), "r"(fn_destruct_addr)
        : "eax", "ecx", "edx", "memory"
    );

    __asm__ __volatile__(
        "movl %0, %%ecx\n\t"
        "call *%1\n\t"
        :
        : "r"(&tjs_name), "r"(fn_destruct_addr)
        : "eax", "ecx", "edx", "memory"
    );
  }
}
