#pragma once

#include <jxl/decode.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <vector>
#include <new>

struct JxlDecodedImage {
  uint32_t width;
  uint32_t height;
  std::vector<uint8_t> bgra;
};

typedef void (*JxlSizeCallback)(void* callback_data, uint32_t width, uint32_t height);
typedef void* (*JxlScanlineCallback)(void* callback_data, int32_t y);

static inline bool SubmitJxlBgra(const JxlDecodedImage& image, void* callback_data,
                                 JxlSizeCallback size, JxlScanlineCallback scanline) {
  if (!size || !scanline || !image.width || !image.height ||
      image.bgra.size() != (size_t)image.width * image.height * 4) return false;
  size(callback_data, image.width, image.height);
  for (uint32_t y = 0; y < image.height; ++y) {
    void* row = scanline(callback_data, (int32_t)y);
    if (!row) return false;
    memcpy(row, image.bgra.data() + (size_t)y * image.width * 4, (size_t)image.width * 4);
    scanline(callback_data, -1);
  }
  return true;
}

static inline bool IsJxlPayload(const uint8_t* data, size_t size) {
  static const uint8_t kContainer[] = {0x00, 0x00, 0x00, 0x0c, 0x4a, 0x58,
                                       0x4c, 0x20, 0x0d, 0x0a, 0x87, 0x0a};
  return (size >= 2 && data[0] == 0xff && data[1] == 0x0a) ||
         (size >= sizeof(kContainer) && memcmp(data, kContainer, sizeof(kContainer)) == 0);
}

static inline bool DecodeJxlToBgra(const uint8_t* input, size_t input_size,
                                   JxlDecodedImage* image) {
  if (!input || !input_size || !image) return false;
  image->width = image->height = 0;
  image->bgra.clear();
  JxlDecoder* decoder = JxlDecoderCreate(NULL);
  if (!decoder) return false;

  bool ok = false, saw_full_image = false;
  JxlPixelFormat format = {4, JXL_TYPE_UINT8, JXL_NATIVE_ENDIAN, 0};
  JxlDecoderSubscribeEvents(decoder, JXL_DEC_BASIC_INFO | JXL_DEC_FULL_IMAGE);
  JxlDecoderSetInput(decoder, input, input_size);
  JxlDecoderCloseInput(decoder);

  try {
    for (;;) {
      JxlDecoderStatus status = JxlDecoderProcessInput(decoder);
      if (status == JXL_DEC_ERROR || status == JXL_DEC_NEED_MORE_INPUT) break;
      if (status == JXL_DEC_BASIC_INFO) {
        JxlBasicInfo info;
        if (JxlDecoderGetBasicInfo(decoder, &info) != JXL_DEC_SUCCESS ||
            !info.xsize || !info.ysize || info.have_animation || info.orientation != 1 ||
            info.num_extra_channels > 1 ||
            (info.num_extra_channels == 1 && info.alpha_bits == 0) ||
            info.xsize > UINT32_MAX / 4 ||
            (uint64_t)info.xsize * info.ysize * 4 > SIZE_MAX) break;
        image->width = info.xsize;
        image->height = info.ysize;
        image->bgra.resize((size_t)info.xsize * info.ysize * 4);
      } else if (status == JXL_DEC_NEED_IMAGE_OUT_BUFFER) {
        size_t required = 0;
        if (image->bgra.empty() ||
            JxlDecoderImageOutBufferSize(decoder, &format, &required) != JXL_DEC_SUCCESS ||
            required != image->bgra.size() ||
            JxlDecoderSetImageOutBuffer(decoder, &format, image->bgra.data(), required) != JXL_DEC_SUCCESS) break;
      } else if (status == JXL_DEC_FULL_IMAGE) {
        if (saw_full_image) break;
        saw_full_image = true;
      } else if (status == JXL_DEC_SUCCESS) {
        if (!saw_full_image) break;
        for (size_t i = 0; i < image->bgra.size(); i += 4) {
          uint8_t red = image->bgra[i];
          image->bgra[i] = image->bgra[i + 2];
          image->bgra[i + 2] = red;
        }
        ok = !image->bgra.empty();
        break;
      }
    }
  } catch (const std::bad_alloc&) {
    ok = false;
  }
  JxlDecoderDestroy(decoder);
  if (!ok) {
    image->width = image->height = 0;
    image->bgra.clear();
  }
  return ok;
}
