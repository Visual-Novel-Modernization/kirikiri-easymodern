#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include <mmreg.h>
#include <msacm.h>
#include <objidl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <string>
#include <vector>
#include <deque>
#include "av1_decode.h"

// KiriKiri engine RVAs in すれ違う兄妹の壊れる倫理観.exe
static const uintptr_t kIsExistentStorageRva   = 0x00037E40;
static const uintptr_t kCreateDsLayerVideoRva  = 0x00087B60;
static const uintptr_t kGetScanlineRva         = 0x0017DFC0;
static const uintptr_t kBaseBitmapCtorRva      = 0x00181440;
static const uintptr_t kSetStatusAsyncRva      = 0x001CFA00;
static const uintptr_t kVideoOverlayOpenRva    = 0x001DD020;
static const uintptr_t kVideoOverlayCloseRva   = 0x001DD520;
static const uintptr_t kClearWndProcMsgsRva    = 0x001DE410;
static const uintptr_t kEngineOperatorNewRva   = 0x002A8F96;

static const uint8_t kExpectedSehPrologue[5] = {0x55, 0x8b, 0xec, 0x6a, 0xff};

// Engine function pointer types
typedef int (__cdecl *IsExistentStorageFn)(uint32_t* result, int numparams, uint32_t** param);
typedef int (__thiscall *VideoOverlayOpenFn)(void* this_ptr, int*** a2);
typedef int (__fastcall *CreateDsLayerVideoFn)(HWND callback_win, void* stream,
                                               const wchar_t* stream_name, const wchar_t* type,
                                               uint32_t size_lo, uint32_t size_hi, void** out_overlay);
typedef void (__thiscall *VideoOverlayCloseFn)(void* this_ptr);
typedef void (__thiscall *ClearWndProcMsgsFn)(void* this_ptr);
typedef int (__thiscall *SetStatusAsyncFn)(void* this_ptr, void* status_code);
typedef void* (__cdecl *EngineOperatorNewFn)(size_t size);
typedef void* (__thiscall *BaseBitmapCtorFn)(void* this_ptr, int width, int height, int bpp);
typedef void* (__thiscall *GetScanlineFn)(void* bitmap_internal, int y);

static volatile LONG g_av1_installed = 0;

static IsExistentStorageFn g_orig_is_existent = nullptr;
static VideoOverlayOpenFn g_orig_open = nullptr;
static CreateDsLayerVideoFn g_orig_create_ds_layer = nullptr;

static BYTE* g_tramp_is_existent = nullptr;
static BYTE* g_tramp_open = nullptr;
static BYTE* g_tramp_create_ds_layer = nullptr;

static VideoOverlayCloseFn g_fn_close = nullptr;
static ClearWndProcMsgsFn g_fn_clear_msgs = nullptr;
static SetStatusAsyncFn g_fn_set_status_async = nullptr;
static EngineOperatorNewFn g_fn_operator_new = nullptr;
static BaseBitmapCtorFn g_fn_bmp_ctor = nullptr;
static GetScanlineFn g_fn_get_scanline = nullptr;

static void Av1Log(const char* format, ...) {
  char text[512];
  va_list args;
  va_start(args, format);
  _vsnprintf(text, sizeof(text) - 1, format, args);
  va_end(args);
  text[sizeof(text) - 1] = '\0';
  OutputDebugStringA("[av1_dav1d_hook] ");
  OutputDebugStringA(text);
  OutputDebugStringA("\n");

  wchar_t directory[MAX_PATH];
  DWORD length = GetModuleFileNameW(NULL, directory, MAX_PATH);
  if (!length || length >= MAX_PATH) return;
  while (length && directory[length - 1] != L'\\' && directory[length - 1] != L'/') --length;
  if (!length || length + 20 >= MAX_PATH) return;
  lstrcpyW(directory + length, L"av1_gst_hook.log");
  HANDLE file = CreateFileW(directory, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file != INVALID_HANDLE_VALUE) {
    char line[560];
    int line_length = _snprintf(line, sizeof(line), "[av1_dav1d_hook] %s\r\n", text);
    DWORD written;
    if (line_length > 0) WriteFile(file, line, (DWORD)line_length, &written, NULL);
    CloseHandle(file);
  }
}

static std::wstring GetGameRootDir() {
  wchar_t exe_path[MAX_PATH] = {};
  DWORD len = GetModuleFileNameW(NULL, exe_path, MAX_PATH);
  if (!len || len >= MAX_PATH) return L".";
  std::wstring dir(exe_path, len);
  size_t pos = dir.find_last_of(L"\\/");
  if (pos != std::wstring::npos) dir.resize(pos);
  return dir;
}

static bool FileExistsW(const std::wstring& path) {
  DWORD attr = GetFileAttributesW(path.c_str());
  return (attr != INVALID_FILE_ATTRIBUTES) && ((attr & FILE_ATTRIBUTE_DIRECTORY) == 0);
}

static std::wstring ExtractStemLower(const wchar_t* wname) {
  if (!wname) return L"";
  std::wstring s(wname);
  size_t slash = s.find_last_of(L"\\/>");
  if (slash != std::wstring::npos) s = s.substr(slash + 1);
  size_t dot = s.find_last_of(L'.');
  if (dot != std::wstring::npos) s = s.substr(0, dot);
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] >= L'A' && s[i] <= L'Z') s[i] = (wchar_t)(s[i] - L'A' + L'a');
  }
  return s;
}

static bool ResolveExternalAv1Path(const wchar_t* wname, std::wstring* out_path) {
  if (!wname || !*wname) return false;
  std::wstring stem = ExtractStemLower(wname);
  if (stem.empty()) return false;

  std::wstring root = GetGameRootDir();
  std::vector<std::wstring> candidates;
  candidates.push_back(root + L"\\" + stem + L"_av1.mp4");
  candidates.push_back(root + L"\\" + stem + L".mp4");
  candidates.push_back(root + L"\\" + stem + L".ivf");
  if (stem.find(L"sureimo") != std::wstring::npos) {
    candidates.push_back(root + L"\\sureimo_av1.mp4");
    candidates.push_back(root + L"\\sureimo.mp4");
  }

  for (size_t i = 0; i < candidates.size(); ++i) {
    if (FileExistsW(candidates[i])) {
      if (out_path) *out_path = candidates[i];
      return true;
    }
  }
  return false;
}

// ============================================================================
// Av1LayerVideoOverlay: Native KiriKiri iTVPVideoOverlay C++ implementation
// ============================================================================
struct PendingMediaEvent {
  long ev_code;
  long param1;
  long param2;
};

class Av1LayerVideoOverlay {
public:
  void** vtbl_;

  static Av1LayerVideoOverlay* CreateFromFile(const std::wstring& path, HWND callback_hwnd) {
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return nullptr;
    LARGE_INTEGER fsz = {};
    if (!GetFileSizeEx(hf, &fsz) || fsz.QuadPart < 32) {
      CloseHandle(hf);
      return nullptr;
    }
    HANDLE hmap = CreateFileMappingW(hf, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hmap) {
      CloseHandle(hf);
      return nullptr;
    }
    const uint8_t* mapped = (const uint8_t*)MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, 0);
    if (!mapped) {
      CloseHandle(hmap);
      CloseHandle(hf);
      return nullptr;
    }

    auto* obj = new (std::nothrow) Av1LayerVideoOverlay(callback_hwnd);
    if (!obj) {
      UnmapViewOfFile(mapped);
      CloseHandle(hmap);
      CloseHandle(hf);
      return nullptr;
    }
    obj->file_handle_ = hf;
    obj->map_handle_ = hmap;
    obj->mapped_view_ = mapped;
    obj->data_ptr_ = mapped;
    obj->data_size_ = (size_t)fsz.QuadPart;

    if (!obj->InitializeDecoder()) {
      delete obj;
      return nullptr;
    }
    return obj;
  }

  static Av1LayerVideoOverlay* CreateFromMemory(std::vector<uint8_t>&& bytes, HWND callback_hwnd) {
    if (bytes.size() < 32) return nullptr;
    auto* obj = new (std::nothrow) Av1LayerVideoOverlay(callback_hwnd);
    if (!obj) return nullptr;
    obj->owned_bytes_ = std::move(bytes);
    obj->data_ptr_ = obj->owned_bytes_.data();
    obj->data_size_ = obj->owned_bytes_.size();

    if (!obj->InitializeDecoder()) {
      delete obj;
      return nullptr;
    }
    return obj;
  }

  ~Av1LayerVideoOverlay() {
    StopPlayback();
    if (dav1d_ctx_) {
      dav1d_close(&dav1d_ctx_);
      dav1d_ctx_ = nullptr;
    }
    if (mapped_view_) {
      UnmapViewOfFile(mapped_view_);
      mapped_view_ = nullptr;
    }
    if (map_handle_) {
      CloseHandle(map_handle_);
      map_handle_ = NULL;
    }
    if (file_handle_ != INVALID_HANDLE_VALUE) {
      CloseHandle(file_handle_);
      file_handle_ = INVALID_HANDLE_VALUE;
    }
    DeleteCriticalSection(&cs_);
  }

private:
  explicit Av1LayerVideoOverlay(HWND callback_hwnd)
      : vtbl_(s_vtable_),
        ref_count_(1),
        callback_hwnd_(callback_hwnd),
        drain_hwnd_(NULL),
        file_handle_(INVALID_HANDLE_VALUE),
        map_handle_(NULL),
        mapped_view_(nullptr),
        data_ptr_(nullptr),
        data_size_(0),
        dav1d_ctx_(nullptr),
        buff1_(nullptr),
        buff2_(nullptr),
        buff_size_(0),
        front_buf_(nullptr),
        status_(0), // 0=Stop, 1=Play, 2=Pause
        current_frame_(0),
        stop_frame_(-1),
        play_rate_(1.0),
        audio_volume_mb_(0),
        audio_balance_(0),
        audio_enabled_(true),
        worker_thread_(NULL),
        stop_requested_(false),
        paused_(false),
        rewind_requested_(false),
        seek_target_frame_(-1) {
    InitializeCriticalSection(&cs_);
  }

  bool InitializeDecoder() {
    if (!ParseMp4Container(data_ptr_, data_size_, &container_)) {
      Av1Log("ParseMp4Container failed on buffer (size=%u)", (unsigned)data_size_);
      return false;
    }

    Dav1dSettings s;
    dav1d_default_settings(&s);
    s.n_threads = 4;
    s.max_frame_delay = 1;
    if (dav1d_open(&dav1d_ctx_, &s) < 0 || !dav1d_ctx_) {
      Av1Log("dav1d_open failed");
      return false;
    }

    // Feed av1C configOBUs if present
    if (!container_.video.config_obus.empty()) {
      Dav1dData cfg = {};
      uint8_t* p = dav1d_data_create(&cfg, container_.video.config_obus.size());
      if (p) {
        memcpy(p, container_.video.config_obus.data(), container_.video.config_obus.size());
        dav1d_send_data(dav1d_ctx_, &cfg);
        if (cfg.sz > 0) dav1d_data_unref(&cfg);
      }
    }

    // Pre-decode frame 0 so initial buffer has valid pixels immediately on Open
    uint32_t w = container_.video.width;
    uint32_t h = container_.video.height;
    first_frame_bgra_.resize((size_t)w * h * 4, 0);
    if (!container_.video.samples.empty()) {
      Dav1dPicture pic = {};
      if (DecodeSingleSample(0, &pic)) {
        ConvertDav1dPictureToBgra(&pic, first_frame_bgra_.data(), w, h, true);
        dav1d_picture_unref(&pic);
      }
      dav1d_flush(dav1d_ctx_);
      if (!container_.video.config_obus.empty()) {
        Dav1dData cfg = {};
        uint8_t* p = dav1d_data_create(&cfg, container_.video.config_obus.size());
        if (p) {
          memcpy(p, container_.video.config_obus.data(), container_.video.config_obus.size());
          dav1d_send_data(dav1d_ctx_, &cfg);
          if (cfg.sz > 0) dav1d_data_unref(&cfg);
        }
      }
    }

    Av1Log("Initialized libdav1d (%s): %ux%u, %u frames @ %.3f fps (%.2fs), audio=%s (%u Hz, %u ch, %u frames)",
           dav1d_version(), w, h, (unsigned)container_.video.samples.size(),
           container_.video.fps, container_.video.duration_sec,
           container_.audio.valid ? "yes" : "no",
           container_.audio.sample_rate, container_.audio.channels,
           (unsigned)container_.audio.samples.size());
    return true;
  }

  bool DecodeSingleSample(size_t sample_idx, Dav1dPicture* out_pic) {
    if (!dav1d_ctx_ || sample_idx >= container_.video.samples.size() || !out_pic) return false;
    const auto& smp = container_.video.samples[sample_idx];
    if (smp.offset + smp.size > data_size_ || smp.size == 0) return false;

    Dav1dData d = {};
    uint8_t* p = dav1d_data_create(&d, smp.size);
    if (!p) return false;
    memcpy(p, data_ptr_ + smp.offset, smp.size);

    bool got_pic = false;
    while (d.sz > 0) {
      int r = dav1d_send_data(dav1d_ctx_, &d);
      if (r < 0 && r != DAV1D_ERR(EAGAIN)) {
        dav1d_data_unref(&d);
        break;
      }
      Dav1dPicture tmp = {};
      while (dav1d_get_picture(dav1d_ctx_, &tmp) == 0) {
        if (got_pic) {
          dav1d_picture_unref(out_pic);
        }
        *out_pic = tmp;
        got_pic = true;
      }
    }
    if (!got_pic) {
      Dav1dPicture tmp = {};
      if (dav1d_get_picture(dav1d_ctx_, &tmp) == 0) {
        *out_pic = tmp;
        got_pic = true;
      }
    }
    return got_pic;
  }

  float ComputeVolumeScale() const {
    long mb = audio_volume_mb_;
    if (!audio_enabled_ || mb <= -9900) return 0.0f;
    if (mb >= 0) return 1.0f;
    return powf(10.0f, (float)mb / 2000.0f);
  }

  void PushUpdateEventLocked(long frame_idx) {
    for (size_t i = 0; i < events_.size(); ++i) {
      if (events_[i].ev_code == 0x8001) {
        events_[i].param1 = frame_idx;
        return;
      }
    }
    events_.push_back({0x8001, frame_idx, 0});
  }

  static DWORD WINAPI WorkerThreadEntry(LPVOID param) {
    auto* self = (Av1LayerVideoOverlay*)param;
    self->RunPlaybackLoop();
    return 0;
  }

  void RunPlaybackLoop() {
    const uint32_t width = container_.video.width;
    const uint32_t height = container_.video.height;
    const size_t total_video = container_.video.samples.size();
    const size_t total_audio = container_.audio.samples.size();

    // Setup ACM MP3 decoder and waveOut if audio track is present
    HACMSTREAM has = NULL;
    HWAVEOUT hwo = NULL;
    static const size_t kNumAudioBuffers = 12;
    static const size_t kMp3FramesPerBuf = 4; // 4 * 1152 = 4608 stereo samples (~96ms)
    WAVEHDR wave_hdrs[kNumAudioBuffers] = {};
    std::vector<uint8_t> wave_pcm[kNumAudioBuffers];
    std::vector<uint8_t> mp3_in_buf;
    std::vector<uint8_t> pcm_out_buf;
    ACMSTREAMHEADER ash = {};
    bool ash_prepared = false;

    if (container_.audio.valid && total_audio > 0 &&
        (container_.audio.object_type_indication == 0x6B || container_.audio.object_type_indication == 0x69 ||
         container_.audio.object_type_indication == 0)) {
      uint32_t avg_bytes = 192000 / 8;
      uint16_t block_sz = (uint16_t)(container_.audio.samples[0].size ? container_.audio.samples[0].size : 576);
      MPEGLAYER3WAVEFORMAT mp3fmt = {};
      mp3fmt.wfx.wFormatTag = WAVE_FORMAT_MPEGLAYER3;
      mp3fmt.wfx.nChannels = container_.audio.channels;
      mp3fmt.wfx.nSamplesPerSec = container_.audio.sample_rate;
      mp3fmt.wfx.nAvgBytesPerSec = avg_bytes;
      mp3fmt.wfx.nBlockAlign = 1;
      mp3fmt.wfx.wBitsPerSample = 0;
      mp3fmt.wfx.cbSize = MPEGLAYER3_WFX_EXTRA_BYTES;
      mp3fmt.wID = MPEGLAYER3_ID_MPEG;
      mp3fmt.fdwFlags = MPEGLAYER3_FLAG_PADDING_OFF;
      mp3fmt.nBlockSize = block_sz;
      mp3fmt.nFramesPerBlock = 1;
      mp3fmt.nCodecDelay = 0;

      WAVEFORMATEX pcmfmt = {};
      pcmfmt.wFormatTag = WAVE_FORMAT_PCM;
      pcmfmt.nChannels = container_.audio.channels;
      pcmfmt.nSamplesPerSec = container_.audio.sample_rate;
      pcmfmt.wBitsPerSample = 16;
      pcmfmt.nBlockAlign = (WORD)(container_.audio.channels * 2);
      pcmfmt.nAvgBytesPerSec = container_.audio.sample_rate * pcmfmt.nBlockAlign;

      if (acmStreamOpen(&has, NULL, (LPWAVEFORMATEX)&mp3fmt, &pcmfmt, NULL, 0, 0, 0) == 0 && has) {
        if (waveOutOpen(&hwo, WAVE_MAPPER, &pcmfmt, 0, 0, CALLBACK_NULL) == MMSYSERR_NOERROR && hwo) {
          mp3_in_buf.resize(4096 * kMp3FramesPerBuf);
          pcm_out_buf.resize(1152 * 4 * kMp3FramesPerBuf * 2);
          ash.cbStruct = sizeof(ash);
          ash.pbSrc = mp3_in_buf.data();
          ash.cbSrcLength = (DWORD)mp3_in_buf.size();
          ash.pbDst = pcm_out_buf.data();
          ash.cbDstLength = (DWORD)pcm_out_buf.size();
          if (acmStreamPrepareHeader(has, &ash, 0) == 0) {
            ash_prepared = true;
            for (size_t i = 0; i < kNumAudioBuffers; ++i) {
              wave_pcm[i].resize(pcm_out_buf.size());
              wave_hdrs[i].lpData = (LPSTR)wave_pcm[i].data();
              wave_hdrs[i].dwBufferLength = (DWORD)wave_pcm[i].size();
              waveOutPrepareHeader(hwo, &wave_hdrs[i], sizeof(WAVEHDR));
              wave_hdrs[i].dwFlags |= WHDR_DONE;
            }
          }
        } else {
          acmStreamClose(has, 0);
          has = NULL;
        }
      }
    }

    size_t next_audio_sample = 0;
    uint64_t audio_base_samples = 0;

    auto refill_audio = [&]() {
      if (!hwo || !has || !ash_prepared || next_audio_sample >= total_audio) return;
      float vol = ComputeVolumeScale();
      for (size_t i = 0; i < kNumAudioBuffers && next_audio_sample < total_audio; ++i) {
        if ((wave_hdrs[i].dwFlags & WHDR_DONE) == 0) continue;
        size_t copy_bytes = 0;
        size_t frames_copied = 0;
        while (frames_copied < kMp3FramesPerBuf && next_audio_sample < total_audio) {
          const auto& asmp = container_.audio.samples[next_audio_sample];
          if (asmp.offset + asmp.size <= data_size_ && copy_bytes + asmp.size <= mp3_in_buf.size()) {
            memcpy(mp3_in_buf.data() + copy_bytes, data_ptr_ + asmp.offset, asmp.size);
            copy_bytes += asmp.size;
          }
          ++next_audio_sample;
          ++frames_copied;
        }
        if (copy_bytes == 0) break;
        ash.cbSrcLength = (DWORD)copy_bytes;
        ash.cbDstLengthUsed = 0;
        if (acmStreamConvert(has, &ash, ACM_STREAMCONVERTF_BLOCKALIGN) == 0 && ash.cbDstLengthUsed > 0) {
          int16_t* dst16 = (int16_t*)wave_pcm[i].data();
          const int16_t* src16 = (const int16_t*)pcm_out_buf.data();
          size_t count16 = ash.cbDstLengthUsed / 2;
          if (vol <= 0.0001f) {
            memset(dst16, 0, ash.cbDstLengthUsed);
          } else if (vol >= 0.999f) {
            memcpy(dst16, src16, ash.cbDstLengthUsed);
          } else {
            int32_t mul = (int32_t)(vol * 32768.0f);
            for (size_t k = 0; k < count16; ++k) {
              int32_t v = ((int32_t)src16[k] * mul) >> 15;
              if (v > 32767) v = 32767;
              if (v < -32768) v = -32768;
              dst16[k] = (int16_t)v;
            }
          }
          wave_hdrs[i].dwFlags &= ~WHDR_DONE;
          wave_hdrs[i].dwBufferLength = ash.cbDstLengthUsed;
          waveOutWrite(hwo, &wave_hdrs[i], sizeof(WAVEHDR));
        }
      }
    };

    LARGE_INTEGER qpf = {}, start_qpc = {};
    QueryPerformanceFrequency(&qpf);

    auto reset_decoder_to_start = [&]() {
      if (dav1d_ctx_) {
        dav1d_flush(dav1d_ctx_);
        if (!container_.video.config_obus.empty()) {
          Dav1dData cfg = {};
          uint8_t* p = dav1d_data_create(&cfg, container_.video.config_obus.size());
          if (p) {
            memcpy(p, container_.video.config_obus.data(), container_.video.config_obus.size());
            dav1d_send_data(dav1d_ctx_, &cfg);
            if (cfg.sz > 0) dav1d_data_unref(&cfg);
          }
        }
      }
      if (hwo) {
        waveOutReset(hwo);
        for (size_t i = 0; i < kNumAudioBuffers; ++i) {
          wave_hdrs[i].dwFlags |= WHDR_DONE;
        }
        MMTIME mmt = {};
        mmt.wType = TIME_SAMPLES;
        if (waveOutGetPosition(hwo, &mmt, sizeof(mmt)) == MMSYSERR_NOERROR && mmt.wType == TIME_SAMPLES) {
          audio_base_samples = mmt.u.sample;
        }
      }
      next_audio_sample = 0;
      QueryPerformanceCounter(&start_qpc);
    };

    reset_decoder_to_start();
    refill_audio();

    size_t frame_idx = 0;
    while (!stop_requested_ && frame_idx < total_video) {
      if (rewind_requested_) {
        rewind_requested_ = false;
        frame_idx = 0;
        reset_decoder_to_start();
        refill_audio();
      }
      int seek_f = seek_target_frame_;
      if (seek_f >= 0) {
        seek_target_frame_ = -1;
        if (seek_f == 0) {
          frame_idx = 0;
          reset_decoder_to_start();
          refill_audio();
        }
      }

      if (paused_) {
        if (hwo) waveOutPause(hwo);
        LARGE_INTEGER pause_t0 = {}, pause_t1 = {};
        QueryPerformanceCounter(&pause_t0);
        while (paused_ && !stop_requested_) {
          Sleep(5);
        }
        QueryPerformanceCounter(&pause_t1);
        start_qpc.QuadPart += (pause_t1.QuadPart - pause_t0.QuadPart);
        if (hwo && !stop_requested_) waveOutRestart(hwo);
        if (stop_requested_) break;
      }

      refill_audio();

      Dav1dPicture pic = {};
      if (DecodeSingleSample(frame_idx, &pic)) {
        uint8_t* back_buf = nullptr;
        EnterCriticalSection(&cs_);
        if (buff1_ && buff2_) {
          back_buf = (front_buf_ == buff1_) ? buff2_ : buff1_;
        }
        LeaveCriticalSection(&cs_);

        if (back_buf) {
          ConvertDav1dPictureToBgra(&pic, back_buf, width, height, true);
        }
        dav1d_picture_unref(&pic);

        double target_sec = container_.video.samples[frame_idx].pts_sec;
        double rate = play_rate_ > 0.05 ? play_rate_ : 1.0;
        target_sec /= rate;

        while (!stop_requested_ && !paused_ && !rewind_requested_) {
          refill_audio();
          double now_sec = 0.0;
          bool got_audio_clock = false;
          if (hwo && container_.audio.sample_rate > 0) {
            MMTIME mmt = {};
            mmt.wType = TIME_SAMPLES;
            if (waveOutGetPosition(hwo, &mmt, sizeof(mmt)) == MMSYSERR_NOERROR && mmt.wType == TIME_SAMPLES) {
              uint64_t played = (mmt.u.sample >= audio_base_samples) ? (mmt.u.sample - audio_base_samples) : 0;
              now_sec = (double)played / (double)container_.audio.sample_rate;
              got_audio_clock = true;
            }
          }
          if (!got_audio_clock) {
            LARGE_INTEGER cur_qpc = {};
            QueryPerformanceCounter(&cur_qpc);
            now_sec = (double)(cur_qpc.QuadPart - start_qpc.QuadPart) / (double)qpf.QuadPart;
          }
          if (now_sec + 0.002 >= target_sec) break;
          double remain_ms = (target_sec - now_sec) * 1000.0;
          Sleep(remain_ms > 4.0 ? 2 : 1);
        }

        if (stop_requested_) break;

        if (back_buf) {
          EnterCriticalSection(&cs_);
          front_buf_ = back_buf;
          current_frame_ = (int)frame_idx;
          PushUpdateEventLocked((long)frame_idx);
          LeaveCriticalSection(&cs_);

          HWND hwnd = drain_hwnd_ ? drain_hwnd_ : callback_hwnd_;
          if (hwnd && IsWindow(hwnd)) {
            PostMessageW(hwnd, 1039, 0, 0); // 0x040F WM_GRAPHNOTIFY -> EC_UPDATE
          }
        }
      }

      int sf = stop_frame_;
      if (sf > 0 && (int)frame_idx >= sf) {
        break;
      }
      ++frame_idx;
    }

    // Drain remaining audio buffers on natural completion
    if (!stop_requested_ && hwo) {
      for (int wait_iter = 0; wait_iter < 100 && !stop_requested_; ++wait_iter) {
        bool all_done = true;
        for (size_t i = 0; i < kNumAudioBuffers; ++i) {
          if ((wave_hdrs[i].dwFlags & WHDR_DONE) == 0) {
            all_done = false;
            break;
          }
        }
        if (all_done) break;
        Sleep(5);
      }
    }

    // Clean up audio handles
    if (hwo) {
      waveOutReset(hwo);
      for (size_t i = 0; i < kNumAudioBuffers; ++i) {
        waveOutUnprepareHeader(hwo, &wave_hdrs[i], sizeof(WAVEHDR));
      }
      waveOutClose(hwo);
      hwo = NULL;
    }
    if (has) {
      if (ash_prepared) acmStreamUnprepareHeader(has, &ash, 0);
      acmStreamClose(has, 0);
      has = NULL;
    }

    if (!stop_requested_) {
      Av1Log("Movie playback finished naturally at frame %u; posting completion notification",
             (unsigned)frame_idx);
      EnterCriticalSection(&cs_);
      status_ = 0;
      LeaveCriticalSection(&cs_);

      HWND hwnd = callback_hwnd_;
      if (hwnd && IsWindow(hwnd)) {
        // Post native TVPQueueWindow message 1042 (0x0412) wParam=4:
        // KiriKiri's WndProc (0x005DDD20) handles loop or calls Stop() + sub_5CFB40(1) ("stop")
        // and returns immediately without touching freed this[7] pointers!
        PostMessageW(hwnd, 1042, 4, 0);
      }
    }
  }

public:
  void StartPlayback() {
    EnterCriticalSection(&cs_);
    if (status_ == 2 && worker_thread_) {
      // Resume from pause
      paused_ = false;
      status_ = 1;
      LeaveCriticalSection(&cs_);
      return;
    }
    LeaveCriticalSection(&cs_);

    StopPlayback();

    EnterCriticalSection(&cs_);
    stop_requested_ = false;
    paused_ = false;
    rewind_requested_ = false;
    status_ = 1;
    // Also post initial frame 0 update immediately
    PushUpdateEventLocked((long)current_frame_);
    LeaveCriticalSection(&cs_);

    HWND hwnd = drain_hwnd_ ? drain_hwnd_ : callback_hwnd_;
    if (hwnd && IsWindow(hwnd)) {
      PostMessageW(hwnd, 1039, 0, 0);
    }

    worker_thread_ = CreateThread(NULL, 0, WorkerThreadEntry, this, 0, NULL);
    Av1Log("StartPlayback launched worker thread=%p", worker_thread_);
  }

  void StopPlayback() {
    stop_requested_ = true;
    paused_ = false;
    HANDLE th = NULL;
    EnterCriticalSection(&cs_);
    th = worker_thread_;
    worker_thread_ = NULL;
    status_ = 0;
    events_.clear();
    LeaveCriticalSection(&cs_);

    if (th) {
      if (GetCurrentThreadId() != GetThreadId(th)) {
        WaitForSingleObject(th, 3000);
      }
      CloseHandle(th);
    }
  }

  // ==========================================================================
  // iTVPVideoOverlay vtable methods (74 slots matching tTVPDSLayerVideo)
  // ==========================================================================
  static void __stdcall VtblAddRef(Av1LayerVideoOverlay* self) {
    InterlockedIncrement(&self->ref_count_);
  }

  static void __stdcall VtblRelease(Av1LayerVideoOverlay* self) {
    if (InterlockedDecrement(&self->ref_count_) <= 0) {
      delete self;
    }
  }

  static void __stdcall VtblSetWindowHandle(Av1LayerVideoOverlay* self, HWND wnd) {
    (void)self;
    (void)wnd;
  }

  static void __stdcall VtblSetMessageDrainWindow(Av1LayerVideoOverlay* self, HWND wnd) {
    self->drain_hwnd_ = wnd;
  }

  static void __stdcall VtblSetRect(Av1LayerVideoOverlay* self, RECT* rect) {
    (void)self;
    (void)rect;
  }

  static void __stdcall VtblSetVisible(Av1LayerVideoOverlay* self, bool b) {
    (void)self;
    (void)b;
  }

  static void __stdcall VtblPlay(Av1LayerVideoOverlay* self) {
    self->StartPlayback();
  }

  static void __stdcall VtblStop(Av1LayerVideoOverlay* self) {
    self->StopPlayback();
  }

  static void __stdcall VtblPause(Av1LayerVideoOverlay* self) {
    EnterCriticalSection(&self->cs_);
    if (self->status_ == 1) {
      self->paused_ = true;
      self->status_ = 2;
    }
    LeaveCriticalSection(&self->cs_);
  }

  static void __stdcall VtblSetPosition(Av1LayerVideoOverlay* self, uint64_t tick_ms) {
    EnterCriticalSection(&self->cs_);
    if (tick_ms == 0) {
      self->current_frame_ = 0;
      self->rewind_requested_ = true;
    } else if (self->container_.video.fps > 0.0) {
      self->current_frame_ = (int)((double)tick_ms * self->container_.video.fps / 1000.0);
    }
    LeaveCriticalSection(&self->cs_);
  }

  static void __stdcall VtblGetPosition(Av1LayerVideoOverlay* self, uint64_t* tick_ms) {
    if (!tick_ms) return;
    EnterCriticalSection(&self->cs_);
    int f = self->current_frame_;
    LeaveCriticalSection(&self->cs_);
    if (f >= 0 && (size_t)f < self->container_.video.samples.size()) {
      *tick_ms = (uint64_t)(self->container_.video.samples[f].pts_sec * 1000.0 + 0.5);
    } else {
      *tick_ms = 0;
    }
  }

  static void __stdcall VtblGetStatus(Av1LayerVideoOverlay* self, int* status) {
    if (!status) return;
    EnterCriticalSection(&self->cs_);
    *status = self->status_;
    LeaveCriticalSection(&self->cs_);
  }

  static void __stdcall VtblGetEvent(Av1LayerVideoOverlay* self, long* ev_code,
                                     long* param1, long* param2, bool* got) {
    if (got) *got = false;
    EnterCriticalSection(&self->cs_);
    if (!self->events_.empty()) {
      PendingMediaEvent ev = self->events_.front();
      self->events_.pop_front();
      if (ev_code) *ev_code = ev.ev_code;
      if (param1) *param1 = ev.param1;
      if (param2) *param2 = ev.param2;
      if (got) *got = true;
    }
    LeaveCriticalSection(&self->cs_);
  }

  static void __stdcall VtblFreeEventParams(Av1LayerVideoOverlay* self, long ev_code,
                                            long param1, long param2) {
    (void)self;
    (void)ev_code;
    (void)param1;
    (void)param2;
  }

  static void __stdcall VtblRewind(Av1LayerVideoOverlay* self) {
    EnterCriticalSection(&self->cs_);
    self->current_frame_ = 0;
    self->rewind_requested_ = true;
    LeaveCriticalSection(&self->cs_);
  }

  static void __stdcall VtblSetFrame(Av1LayerVideoOverlay* self, int f) {
    EnterCriticalSection(&self->cs_);
    self->current_frame_ = f >= 0 ? f : 0;
    self->seek_target_frame_ = self->current_frame_;
    LeaveCriticalSection(&self->cs_);
  }

  static void __stdcall VtblGetFrame(Av1LayerVideoOverlay* self, int* f) {
    if (!f) return;
    EnterCriticalSection(&self->cs_);
    *f = self->current_frame_;
    LeaveCriticalSection(&self->cs_);
  }

  static void __stdcall VtblGetFPS(Av1LayerVideoOverlay* self, double* f) {
    if (f) *f = self->container_.video.fps;
  }

  static void __stdcall VtblGetNumberOfFrame(Av1LayerVideoOverlay* self, int* f) {
    if (f) *f = (int)self->container_.video.samples.size();
  }

  static void __stdcall VtblGetTotalTime(Av1LayerVideoOverlay* self, int64_t* t) {
    if (t) *t = (int64_t)(self->container_.video.duration_sec * 1000.0 + 0.5);
  }

  static void __stdcall VtblGetVideoSize(Av1LayerVideoOverlay* self, long* width, long* height) {
    if (width) *width = (long)self->container_.video.width;
    if (height) *height = (long)self->container_.video.height;
  }

  static void __stdcall VtblGetFrontBuffer(Av1LayerVideoOverlay* self, BYTE** buff) {
    if (!buff) return;
    EnterCriticalSection(&self->cs_);
    *buff = self->front_buf_;
    LeaveCriticalSection(&self->cs_);
  }

  static void __stdcall VtblSetVideoBuffer(Av1LayerVideoOverlay* self, BYTE* buff1, BYTE* buff2, long size) {
    EnterCriticalSection(&self->cs_);
    self->buff1_ = buff1;
    self->buff2_ = buff2;
    self->buff_size_ = size;
    self->front_buf_ = buff1;
    if (!self->first_frame_bgra_.empty() && (size_t)size >= self->first_frame_bgra_.size()) {
      if (buff1) memcpy(buff1, self->first_frame_bgra_.data(), self->first_frame_bgra_.size());
      if (buff2) memcpy(buff2, self->first_frame_bgra_.data(), self->first_frame_bgra_.size());
    }
    LeaveCriticalSection(&self->cs_);
  }

  static void __stdcall VtblSetStopFrame(Av1LayerVideoOverlay* self, int frame) {
    self->stop_frame_ = frame;
  }

  static void __stdcall VtblGetStopFrame(Av1LayerVideoOverlay* self, int* frame) {
    if (frame) *frame = self->stop_frame_;
  }

  static void __stdcall VtblSetDefaultStopFrame(Av1LayerVideoOverlay* self) {
    self->stop_frame_ = -1;
  }

  static void __stdcall VtblSetPlayRate(Av1LayerVideoOverlay* self, double rate) {
    if (rate > 0.0) self->play_rate_ = rate;
  }

  static void __stdcall VtblGetPlayRate(Av1LayerVideoOverlay* self, double* rate) {
    if (rate) *rate = self->play_rate_;
  }

  static void __stdcall VtblSetAudioBalance(Av1LayerVideoOverlay* self, long balance) {
    self->audio_balance_ = balance;
  }

  static void __stdcall VtblGetAudioBalance(Av1LayerVideoOverlay* self, long* balance) {
    if (balance) *balance = self->audio_balance_;
  }

  static void __stdcall VtblSetAudioVolume(Av1LayerVideoOverlay* self, long volume) {
    self->audio_volume_mb_ = volume;
  }

  static void __stdcall VtblGetAudioVolume(Av1LayerVideoOverlay* self, long* volume) {
    if (volume) *volume = self->audio_volume_mb_;
  }

  static void __stdcall VtblGetNumberOfAudioStream(Av1LayerVideoOverlay* self, unsigned long* count) {
    if (count) *count = self->container_.audio.valid ? 1UL : 0UL;
  }

  static void __stdcall VtblSelectAudioStream(Av1LayerVideoOverlay* self, unsigned long num) {
    (void)num;
    self->audio_enabled_ = true;
  }

  static void __stdcall VtblGetEnableAudioStreamNum(Av1LayerVideoOverlay* self, long* num) {
    if (num) *num = (self->container_.audio.valid && self->audio_enabled_) ? 0L : -1L;
  }

  static void __stdcall VtblDisableAudioStream(Av1LayerVideoOverlay* self) {
    self->audio_enabled_ = false;
  }

  static void __stdcall VtblGetNumberOfVideoStream(Av1LayerVideoOverlay* self, unsigned long* count) {
    if (count) *count = self->container_.video.valid ? 1UL : 0UL;
  }

  static void __stdcall VtblSelectVideoStream(Av1LayerVideoOverlay* self, unsigned long num) {
    (void)self;
    (void)num;
  }

  static void __stdcall VtblGetEnableVideoStreamNum(Av1LayerVideoOverlay* self, long* num) {
    if (num) *num = 0L;
  }

  static void __stdcall VtblSetMixingBitmap(Av1LayerVideoOverlay* self, HDC hdc, RECT* dest, float alpha) {
    (void)self;
    (void)hdc;
    (void)dest;
    (void)alpha;
  }

  static void __stdcall VtblNoop1(Av1LayerVideoOverlay* self) {
    (void)self;
  }

  static void __stdcall VtblNoop2(Av1LayerVideoOverlay* self, uint32_t* out_or_val) {
    (void)self;
    (void)out_or_val;
  }

  static void* __fastcall VtblScalarDeletingDtor(Av1LayerVideoOverlay* self, void* edx_unused, int flags) {
    (void)edx_unused;
    self->~Av1LayerVideoOverlay();
    if (flags & 1) {
      operator delete(self);
    }
    return self;
  }

  static int __stdcall VtblBuildGraph(Av1LayerVideoOverlay* self, int a1, int a2,
                                      int a3, int a4, int a5, int a6) {
    (void)self;
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    return 0;
  }

  static int __stdcall VtblReleaseAll(Av1LayerVideoOverlay* self) {
    self->StopPlayback();
    return 0;
  }

  static int __cdecl VtblUnknown73(Av1LayerVideoOverlay* self) {
    (void)self;
    return 0;
  }

private:
  volatile LONG ref_count_;
  HWND callback_hwnd_;
  HWND drain_hwnd_;
  HANDLE file_handle_;
  HANDLE map_handle_;
  const uint8_t* mapped_view_;
  std::vector<uint8_t> owned_bytes_;
  const uint8_t* data_ptr_;
  size_t data_size_;
  Mp4ContainerInfo container_;
  Dav1dContext* dav1d_ctx_;
  std::vector<uint8_t> first_frame_bgra_;

  CRITICAL_SECTION cs_;
  BYTE* buff1_;
  BYTE* buff2_;
  long buff_size_;
  BYTE* front_buf_;
  int status_;
  int current_frame_;
  int stop_frame_;
  double play_rate_;
  volatile long audio_volume_mb_;
  volatile long audio_balance_;
  volatile bool audio_enabled_;
  std::deque<PendingMediaEvent> events_;

  HANDLE worker_thread_;
  volatile bool stop_requested_;
  volatile bool paused_;
  volatile bool rewind_requested_;
  volatile int seek_target_frame_;

  static void* s_vtable_[74];
};

void* Av1LayerVideoOverlay::s_vtable_[74] = {
  (void*)Av1LayerVideoOverlay::VtblAddRef,                  // 0 (+0x00)
  (void*)Av1LayerVideoOverlay::VtblRelease,                 // 1 (+0x04)
  (void*)Av1LayerVideoOverlay::VtblSetWindowHandle,         // 2 (+0x08)
  (void*)Av1LayerVideoOverlay::VtblSetMessageDrainWindow,   // 3 (+0x0C)
  (void*)Av1LayerVideoOverlay::VtblSetRect,                 // 4 (+0x10)
  (void*)Av1LayerVideoOverlay::VtblSetVisible,              // 5 (+0x14)
  (void*)Av1LayerVideoOverlay::VtblPlay,                    // 6 (+0x18)
  (void*)Av1LayerVideoOverlay::VtblStop,                    // 7 (+0x1C)
  (void*)Av1LayerVideoOverlay::VtblPause,                   // 8 (+0x20)
  (void*)Av1LayerVideoOverlay::VtblSetPosition,             // 9 (+0x24)
  (void*)Av1LayerVideoOverlay::VtblGetPosition,             // 10 (+0x28)
  (void*)Av1LayerVideoOverlay::VtblGetStatus,               // 11 (+0x2C)
  (void*)Av1LayerVideoOverlay::VtblGetEvent,                // 12 (+0x30)
  (void*)Av1LayerVideoOverlay::VtblFreeEventParams,         // 13 (+0x34)
  (void*)Av1LayerVideoOverlay::VtblRewind,                  // 14 (+0x38)
  (void*)Av1LayerVideoOverlay::VtblSetFrame,                // 15 (+0x3C)
  (void*)Av1LayerVideoOverlay::VtblGetFrame,                // 16 (+0x40)
  (void*)Av1LayerVideoOverlay::VtblGetFPS,                  // 17 (+0x44)
  (void*)Av1LayerVideoOverlay::VtblGetNumberOfFrame,        // 18 (+0x48)
  (void*)Av1LayerVideoOverlay::VtblGetTotalTime,            // 19 (+0x4C)
  (void*)Av1LayerVideoOverlay::VtblGetVideoSize,            // 20 (+0x50)
  (void*)Av1LayerVideoOverlay::VtblGetFrontBuffer,          // 21 (+0x54)
  (void*)Av1LayerVideoOverlay::VtblSetVideoBuffer,          // 22 (+0x58)
  (void*)Av1LayerVideoOverlay::VtblSetStopFrame,            // 23 (+0x5C)
  (void*)Av1LayerVideoOverlay::VtblGetStopFrame,            // 24 (+0x60)
  (void*)Av1LayerVideoOverlay::VtblSetDefaultStopFrame,     // 25 (+0x64)
  (void*)Av1LayerVideoOverlay::VtblSetPlayRate,             // 26 (+0x68)
  (void*)Av1LayerVideoOverlay::VtblGetPlayRate,             // 27 (+0x6C)
  (void*)Av1LayerVideoOverlay::VtblSetAudioBalance,         // 28 (+0x70)
  (void*)Av1LayerVideoOverlay::VtblGetAudioBalance,         // 29 (+0x74)
  (void*)Av1LayerVideoOverlay::VtblSetAudioVolume,          // 30 (+0x78)
  (void*)Av1LayerVideoOverlay::VtblGetAudioVolume,          // 31 (+0x7C)
  (void*)Av1LayerVideoOverlay::VtblGetNumberOfAudioStream,  // 32 (+0x80)
  (void*)Av1LayerVideoOverlay::VtblSelectAudioStream,       // 33 (+0x84)
  (void*)Av1LayerVideoOverlay::VtblGetEnableAudioStreamNum, // 34 (+0x88)
  (void*)Av1LayerVideoOverlay::VtblDisableAudioStream,      // 35 (+0x8C)
  (void*)Av1LayerVideoOverlay::VtblGetNumberOfVideoStream,  // 36 (+0x90)
  (void*)Av1LayerVideoOverlay::VtblSelectVideoStream,       // 37 (+0x94)
  (void*)Av1LayerVideoOverlay::VtblGetEnableVideoStreamNum, // 38 (+0x98)
  (void*)Av1LayerVideoOverlay::VtblSetMixingBitmap,         // 39 (+0x9C)
  (void*)Av1LayerVideoOverlay::VtblNoop1,                   // 40 (+0xA0)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 41 (+0xA4)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 42 (+0xA8)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 43 (+0xAC)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 44 (+0xB0)
  (void*)Av1LayerVideoOverlay::VtblNoop1,                   // 45 (+0xB4)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 46 (+0xB8)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 47 (+0xBC)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 48 (+0xC0)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 49 (+0xC4)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 50 (+0xC8)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 51 (+0xCC)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 52 (+0xD0)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 53 (+0xD4)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 54 (+0xD8)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 55 (+0xDC)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 56 (+0xE0)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 57 (+0xE4)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 58 (+0xE8)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 59 (+0xEC)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 60 (+0xF0)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 61 (+0xF4)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 62 (+0xF8)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 63 (+0xFC)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 64 (+0x100)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 65 (+0x104)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 66 (+0x108)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 67 (+0x10C)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 68 (+0x110)
  (void*)Av1LayerVideoOverlay::VtblNoop2,                   // 69 (+0x114)
  (void*)Av1LayerVideoOverlay::VtblScalarDeletingDtor,      // 70 (+0x118)
  (void*)Av1LayerVideoOverlay::VtblBuildGraph,              // 71 (+0x11C)
  (void*)Av1LayerVideoOverlay::VtblReleaseAll,              // 72 (+0x120)
  (void*)Av1LayerVideoOverlay::VtblUnknown73                // 73 (+0x124)
};

// ============================================================================
// Engine Hook Handlers
// ============================================================================
static const wchar_t* ExtractTjsVariantString(const uint32_t* var_ptr) {
  if (!var_ptr || var_ptr[2] != 2) return L""; // 2 = tvtString
  const int* s = (const int*)(uintptr_t)var_ptr[0];
  if (!s) return L"";
  const wchar_t* p = (const wchar_t*)(uintptr_t)s[1];
  if (!p) p = (const wchar_t*)(s + 2);
  return p ? p : L"";
}

static const wchar_t* GetTjsStringPtr(int*** a2) {
  if (!a2 || !*a2) return L"";
  int* v3 = (int*)*a2;
  const wchar_t* v5 = (const wchar_t*)v3[1];
  if (!v5) v5 = (const wchar_t*)(v3 + 2);
  return v5 ? v5 : L"";
}

static int __cdecl HookIsExistentStorage(uint32_t* result, int numparams, uint32_t** param) {
  int hr = 0;
  if (g_orig_is_existent) {
    hr = g_orig_is_existent(result, numparams, param);
  }
  if (hr == 0 && result && numparams >= 1 && param && param[0]) {
    if (result[2] == 4 && result[0] == 0) {
      const wchar_t* wname = ExtractTjsVariantString(param[0]);
      if (wname && *wname) {
        std::wstring ext_path;
        if (ResolveExternalAv1Path(wname, &ext_path)) {
          result[0] = 1;
          result[1] = 0;
          result[2] = 4; // tvtInteger
          Av1Log("Storages.isExistentStorage('%ls') -> resolved to '%ls'", wname, ext_path.c_str());
        }
      }
    }
  }
  return hr;
}

static int __fastcall HookCreateDsLayerVideoOverlay(HWND callback_win, void* stream,
                                                    const wchar_t* stream_name, const wchar_t* type,
                                                    uint32_t size_lo, uint32_t size_hi, void** out_overlay) {
  if (stream && out_overlay) {
    IStream* istream = (IStream*)stream;
    LARGE_INTEGER zero = {};
    ULARGE_INTEGER start_pos = {};
    if (SUCCEEDED(istream->Seek(zero, STREAM_SEEK_CUR, &start_pos))) {
      uint8_t probe[16] = {};
      ULONG got = 0;
      istream->Read(probe, sizeof(probe), &got);
      LARGE_INTEGER restore = {};
      restore.QuadPart = (LONGLONG)start_pos.QuadPart;
      istream->Seek(restore, STREAM_SEEK_SET, NULL);

      if (IsAv1Mp4Header(probe, got)) {
        uint64_t total_sz = ((uint64_t)size_hi << 32) | size_lo;
        if (total_sz >= 32 && total_sz <= 512ULL * 1024 * 1024) {
          std::vector<uint8_t> bytes((size_t)total_sz);
          ULONG read_total = 0;
          if (SUCCEEDED(istream->Read(bytes.data(), (ULONG)total_sz, &read_total)) && read_total == total_sz) {
            auto* overlay = Av1LayerVideoOverlay::CreateFromMemory(std::move(bytes), callback_win);
            if (overlay) {
              *out_overlay = overlay;
              Av1Log("Created Av1LayerVideoOverlay from archive stream '%ls' (%u bytes)",
                     stream_name ? stream_name : L"", (unsigned)total_sz);
              return 0;
            }
          }
          istream->Seek(restore, STREAM_SEEK_SET, NULL);
        }
      }
    }
  }
  if (g_orig_create_ds_layer) {
    return g_orig_create_ds_layer(callback_win, stream, stream_name, type, size_lo, size_hi, out_overlay);
  }
  return -1;
}

static int __fastcall HookVideoOverlayOpen(void* this_ptr, void* edx_unused, int*** a2) {
  (void)edx_unused;
  const wchar_t* wname = GetTjsStringPtr(a2);
  Av1Log("VideoOverlay::Open requested: '%ls'", wname);

  std::wstring ext_av1_path;
  if (ResolveExternalAv1Path(wname, &ext_av1_path) &&
      g_fn_close && g_fn_operator_new && g_fn_bmp_ctor && g_fn_get_scanline &&
      g_fn_clear_msgs && g_fn_set_status_async) {
    // 1. Cleanly close any existing overlay and free bitmaps on this_ptr
    g_fn_close(this_ptr);

    HWND callback_hwnd = *(HWND*)((uint8_t*)this_ptr + 0x3C);
    auto* overlay = Av1LayerVideoOverlay::CreateFromFile(ext_av1_path, callback_hwnd);
    if (overlay) {
      *(void**)((uint8_t*)this_ptr + 0x1C) = overlay;

      int32_t mode = *(int32_t*)((uint8_t*)this_ptr + 0x84);
      if (mode == 1) { // vomLayer
        long width = 0, height = 0;
        Av1LayerVideoOverlay::VtblGetVideoSize(overlay, &width, &height);
        if (width > 0 && height > 0) {
          void* raw_bmp0 = g_fn_operator_new(0x50);
          void* bmp0 = g_fn_bmp_ctor(raw_bmp0, (int)width, (int)height, 32);
          *(void**)((uint8_t*)this_ptr + 0x8C) = bmp0;

          void* raw_bmp1 = g_fn_operator_new(0x50);
          void* bmp1 = g_fn_bmp_ctor(raw_bmp1, (int)width, (int)height, 32);
          *(void**)((uint8_t*)this_ptr + 0x90) = bmp1;

          void* internal0 = *(void**)((uint8_t*)bmp0 + 0x48);
          int h0 = *(int*)((uint8_t*)internal0 + 0x18);
          void* bits0 = g_fn_get_scanline(internal0, h0 - 1);
          *(void**)((uint8_t*)this_ptr + 0x94) = bits0;

          void* internal1 = *(void**)((uint8_t*)bmp1 + 0x48);
          int h1 = *(int*)((uint8_t*)internal1 + 0x18);
          void* bits1 = g_fn_get_scanline(internal1, h1 - 1);
          *(void**)((uint8_t*)this_ptr + 0x98) = bits1;

          Av1LayerVideoOverlay::VtblSetVideoBuffer(overlay, (BYTE*)bits0, (BYTE*)bits1, width * height * 4);
        }
      }

      g_fn_clear_msgs(this_ptr);
      g_fn_set_status_async(this_ptr, (void*)1); // 1 = vsStop
      Av1Log("VideoOverlay::Open attached libdav1d overlay for '%ls' (this=%p, hwnd=%p)",
             ext_av1_path.c_str(), this_ptr, callback_hwnd);
      return (int)(uintptr_t)this_ptr;
    }
  }

  if (g_orig_open) {
    return g_orig_open(this_ptr, a2);
  }
  return 0;
}

static bool InstallDetour5(BYTE* target, void* hook_fn, BYTE** out_trampoline, void** out_original) {
  if (target[0] == 0xe9) {
    Av1Log("Target %p already has a detour jump; skipping duplicate installation", target);
    return true;
  }
  if (memcmp(target, kExpectedSehPrologue, sizeof(kExpectedSehPrologue)) != 0) {
    Av1Log("Prologue mismatch at target %p (%02x %02x %02x %02x %02x)",
           target, target[0], target[1], target[2], target[3], target[4]);
    return false;
  }

  BYTE* trampoline = (BYTE*)VirtualAlloc(NULL, 10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!trampoline) return false;

  memcpy(trampoline, target, 5);
  trampoline[5] = 0xe9;
  *(int32_t*)(trampoline + 6) = (int32_t)((target + 5) - (trampoline + 10));

  DWORD old_protect = 0;
  if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old_protect)) {
    VirtualFree(trampoline, 0, MEM_RELEASE);
    return false;
  }

  BYTE patch[5] = {0xe9};
  *(int32_t*)(patch + 1) = (int32_t)((BYTE*)hook_fn - (target + 5));
  memcpy(target, patch, 5);
  FlushInstructionCache(GetCurrentProcess(), target, 5);
  FlushInstructionCache(GetCurrentProcess(), trampoline, 10);
  VirtualProtect(target, 5, old_protect, &old_protect);

  *out_trampoline = trampoline;
  *out_original = (void*)trampoline;
  return true;
}

static bool InstallAllAv1Hooks() {
  HMODULE base = GetModuleHandleW(NULL);
  if (!base) return false;

  uintptr_t base_addr = (uintptr_t)base;
  g_fn_close            = (VideoOverlayCloseFn)(base_addr + kVideoOverlayCloseRva);
  g_fn_clear_msgs       = (ClearWndProcMsgsFn)(base_addr + kClearWndProcMsgsRva);
  g_fn_set_status_async = (SetStatusAsyncFn)(base_addr + kSetStatusAsyncRva);
  g_fn_operator_new     = (EngineOperatorNewFn)(base_addr + kEngineOperatorNewRva);
  g_fn_bmp_ctor         = (BaseBitmapCtorFn)(base_addr + kBaseBitmapCtorRva);
  g_fn_get_scanline     = (GetScanlineFn)(base_addr + kGetScanlineRva);

  bool ok_exist = InstallDetour5((BYTE*)(base_addr + kIsExistentStorageRva),
                                 (void*)HookIsExistentStorage,
                                 &g_tramp_is_existent, (void**)&g_orig_is_existent);
  bool ok_layer = InstallDetour5((BYTE*)(base_addr + kCreateDsLayerVideoRva),
                                 (void*)HookCreateDsLayerVideoOverlay,
                                 &g_tramp_create_ds_layer, (void**)&g_orig_create_ds_layer);
  bool ok_open  = InstallDetour5((BYTE*)(base_addr + kVideoOverlayOpenRva),
                                 (void*)HookVideoOverlayOpen,
                                 &g_tramp_open, (void**)&g_orig_open);

  Av1Log("Installed libdav1d (%s) hooks: isExistentStorage=%s CreateDSLayerVideo=%s VideoOverlay::Open=%s",
         dav1d_version(),
         ok_exist ? "OK" : "FAIL",
         ok_layer ? "OK" : "FAIL",
         ok_open  ? "OK" : "FAIL");
  return ok_open || ok_layer;
}

extern "C" __declspec(dllexport) HRESULT __stdcall V2Link(void* exporter) {
  (void)exporter;
  if (InterlockedCompareExchange(&g_av1_installed, 1, 0) != 0) return S_OK;
  InstallAllAv1Hooks();
  return S_OK;
}

extern "C" __declspec(dllexport) HRESULT __stdcall V2Unlink(void) {
  if (InterlockedCompareExchange(&g_av1_installed, 1, 1) == 1) {
    Av1Log("V2Unlink: refusing dynamic unload for process stability");
    return E_FAIL;
  }
  return S_OK;
}

extern "C" __declspec(dllexport) const char* __stdcall GetActiveAv1Decoder(void) {
  return dav1d_version();
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
