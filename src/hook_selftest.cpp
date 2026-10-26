#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <vector>
#include <algorithm>
#include "jxl_decode.h"
#include "tlg_hybrid.h"
#include "av1_decode.h"

static bool HashSha256(const std::vector<uint8_t>& bytes, char out[65]) {
  HCRYPTPROV p = 0;
  HCRYPTHASH h = 0;
  BYTE digest[32];
  DWORD n = 32;
  bool ok = CryptAcquireContextW(&p, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
            CryptCreateHash(p, CALG_SHA_256, 0, 0, &h) &&
            CryptHashData(h, bytes.data(), (DWORD)bytes.size(), 0) &&
            CryptGetHashParam(h, HP_HASHVAL, digest, &n, 0) && n == 32;
  if (ok) {
    for (unsigned i = 0; i < 32; ++i) sprintf(out + i * 2, "%02x", digest[i]);
    out[64] = 0;
  }
  if (h) CryptDestroyHash(h);
  if (p) CryptReleaseContext(p, 0);
  return ok;
}

struct ProbeContext {
  uint32_t width = 0;
  uint32_t height = 0;
  uint32_t next = 0;
  uint32_t commits = 0;
  uint32_t sizes = 0;
  bool pending = false;
  bool valid = true;
  std::vector<uint8_t> bytes;
};

static void __cdecl MockSizeCallback(void* data, uint32_t w, uint32_t h) {
  auto p = (ProbeContext*)data;
  if (++p->sizes != 1 || !w || !h) p->valid = false;
  p->width = w;
  p->height = h;
  p->bytes.assign((size_t)w * h * 4, 0);
}

static void* __cdecl MockScanlineCallback(void* data, int32_t y) {
  auto p = (ProbeContext*)data;
  if (y == -1) {
    if (!p->pending) p->valid = false;
    p->pending = false;
    ++p->commits;
    return nullptr;
  }
  if (p->sizes != 1 || p->pending || y < 0 || (uint32_t)y != p->next || (uint32_t)y >= p->height) {
    p->valid = false;
    return nullptr;
  }
  p->pending = true;
  ++p->next;
  return p->bytes.data() + (size_t)y * p->width * 4;
}

int wmain(int argc, wchar_t** argv) {
  if (argc == 2 && !wcscmp(argv[1], L"--version")) {
    unsigned v = JxlDecoderVersion();
    printf("{\"decoder_version\":%u,\"version\":\"%u.%u.%u\",\"dav1d_version\":\"%s\"}\n",
           v, v / 1000000, (v / 1000) % 1000, v % 1000, dav1d_version());
    return 0;
  }

  if (argc == 4 && !wcscmp(argv[1], L"--bgra")) {
    HANDLE f = CreateFileW(argv[2], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return 3;

    LARGE_INTEGER length;
    std::vector<uint8_t> input;
    DWORD got;
    bool ok = GetFileSizeEx(f, &length) && length.QuadPart > 0 && length.QuadPart <= 512LL * 1024 * 1024;
    if (ok) {
      input.resize((size_t)length.QuadPart);
      ok = ReadFile(f, input.data(), (DWORD)input.size(), &got, nullptr) && got == input.size();
    }
    CloseHandle(f);
    if (!ok) return 3;

    ProbeContext probe;
    JxlDecodedImage image;
    if (!DecodeJxlToBgra(input.data(), input.size(), &image)) return 6;
    if (!SubmitJxlBgra(image, &probe, MockSizeCallback, MockScanlineCallback)) return 7;

    char payloadHash[65], callbackHash[65];
    if (!HashSha256(input, payloadHash) || !HashSha256(probe.bytes, callbackHash)) return 10;

    f = CreateFileW(argv[3], GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return 11;
    DWORD written;
    ok = WriteFile(f, probe.bytes.data(), (DWORD)probe.bytes.size(), &written, nullptr) && written == probe.bytes.size();
    CloseHandle(f);
    if (!ok) return 11;

    unsigned v = JxlDecoderVersion();
    printf("{\"width\":%u,\"height\":%u,\"payload_sha256\":\"%s\",\"callback_sha256\":\"%s\",\"decoder_version\":%u,\"version\":\"%u.%u.%u\",\"commits\":%u,\"valid\":true}\n",
           probe.width, probe.height, payloadHash, callbackHash, v, v / 1000000, (v / 1000) % 1000, v % 1000, probe.commits);
    return 0;
  }

  if (argc == 3 && !wcscmp(argv[1], L"--test-tlg0-tags")) {
    HANDLE f = CreateFileW(argv[2], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return 3;
    LARGE_INTEGER length;
    std::vector<uint8_t> input;
    DWORD got;
    bool ok = GetFileSizeEx(f, &length) && length.QuadPart > 0 && length.QuadPart <= 64LL * 1024 * 1024;
    if (ok) {
      input.resize((size_t)length.QuadPart);
      ok = ReadFile(f, input.data(), (DWORD)input.size(), &got, nullptr) && got == input.size();
    }
    CloseHandle(f);
    if (!ok) return 3;

    std::vector<TlgTagEntry> tags;
    ParseTlgTagsChunk(input.data(), input.size(), tags);
    printf("{\"tags_count\":%u,\"valid\":true}\n", (unsigned)tags.size());
    return 0;
  }

  if (argc == 3 && !wcscmp(argv[1], L"--av1-info")) {
    HANDLE hf = CreateFileW(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 3;
    LARGE_INTEGER fsz = {};
    if (!GetFileSizeEx(hf, &fsz) || fsz.QuadPart < 32) {
      CloseHandle(hf);
      return 3;
    }
    HANDLE hmap = CreateFileMappingW(hf, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hmap) {
      CloseHandle(hf);
      return 3;
    }
    const uint8_t* base = (const uint8_t*)MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
      CloseHandle(hmap);
      CloseHandle(hf);
      return 3;
    }

    Mp4ContainerInfo info;
    bool ok = ParseMp4Container(base, (size_t)fsz.QuadPart, &info);
    int decoded = 0;
    if (ok && !info.video.samples.empty()) {
      Dav1dSettings s;
      dav1d_default_settings(&s);
      s.n_threads = 2;
      s.max_frame_delay = 1;
      Dav1dContext* ctx = NULL;
      if (dav1d_open(&ctx, &s) == 0 && ctx) {
        std::vector<uint8_t> bgra((size_t)info.video.width * info.video.height * 4);
        for (size_t i = 0; i < 10 && i < info.video.samples.size(); ++i) {
          const auto& smp = info.video.samples[i];
          Dav1dData d = {};
          uint8_t* p = dav1d_data_create(&d, smp.size);
          memcpy(p, base + smp.offset, smp.size);
          while (d.sz > 0) {
            int r = dav1d_send_data(ctx, &d);
            if (r < 0 && r != DAV1D_ERR(EAGAIN)) break;
            Dav1dPicture pic = {};
            while (dav1d_get_picture(ctx, &pic) == 0) {
              if (decoded == 0) {
                ConvertDav1dPictureToBgra(&pic, bgra.data(), info.video.width, info.video.height, true);
              }
              dav1d_picture_unref(&pic);
              ++decoded;
            }
          }
        }
        dav1d_close(&ctx);
      }
    }

    UnmapViewOfFile(base);
    CloseHandle(hmap);
    CloseHandle(hf);
    if (!ok || decoded == 0) return 6;

    printf("{\"width\":%u,\"height\":%u,\"video_samples\":%u,\"fps\":%.3f,\"duration_sec\":%.3f,\"audio_valid\":%s,\"audio_samples\":%u,\"decoded_probe_frames\":%d,\"dav1d_version\":\"%s\",\"valid\":true}\n",
           info.video.width, info.video.height, (unsigned)info.video.samples.size(),
           info.video.fps, info.video.duration_sec,
           info.audio.valid ? "true" : "false", (unsigned)info.audio.samples.size(),
           decoded, dav1d_version());
    return 0;
  }

  fwprintf(stderr, L"usage: hook_selftest --version | --bgra input.jxl output.bgra | --test-tlg0-tags chunk.bin | --av1-info video.mp4\n");
  return 2;
}
