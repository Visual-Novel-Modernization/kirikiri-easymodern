#pragma once
#include <jxl/decode.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <vector>
#include <new>

struct JxlDecodedImage {
  uint32_t width = 0, height = 0;
  std::vector<uint8_t> bgra;
};

static inline bool IsJxlPayload(const uint8_t* data, size_t size) {
  static const uint8_t container[] = {0,0,0,12,0x4a,0x58,0x4c,0x20,13,10,0x87,10};
  return data && ((size >= 2 && data[0] == 0xff && data[1] == 0x0a) ||
    (size >= sizeof(container) && memcmp(data, container, sizeof(container)) == 0));
}

static inline bool DecodeJxlToBgra(const uint8_t* input, size_t length, JxlDecodedImage* image) {
  if (!input || !length || !image) return false;
  *image = JxlDecodedImage{};
  JxlDecoder* decoder = JxlDecoderCreate(nullptr);
  if (!decoder) return false;
  bool ok = false, complete = false;
  JxlPixelFormat format = {4, JXL_TYPE_UINT8, JXL_NATIVE_ENDIAN, 0};
  if (JxlDecoderSubscribeEvents(decoder, JXL_DEC_BASIC_INFO | JXL_DEC_FULL_IMAGE) != JXL_DEC_SUCCESS ||
      JxlDecoderSetInput(decoder, input, length) != JXL_DEC_SUCCESS) {
    JxlDecoderDestroy(decoder); return false;
  }
  JxlDecoderCloseInput(decoder);
  try {
    for (;;) {
      JxlDecoderStatus status = JxlDecoderProcessInput(decoder);
      if (status == JXL_DEC_BASIC_INFO) {
        JxlBasicInfo info;
        if (JxlDecoderGetBasicInfo(decoder, &info) != JXL_DEC_SUCCESS ||
            !info.xsize || !info.ysize || info.have_animation || info.orientation != 1 ||
            info.bits_per_sample != 8 || info.exponent_bits_per_sample != 0 ||
            info.num_extra_channels > 1 || (info.num_extra_channels == 1 && info.alpha_bits != 8) ||
            info.alpha_premultiplied || info.xsize > UINT32_MAX / 4 ||
            (uint64_t)info.xsize * info.ysize * 4 > 512ULL * 1024 * 1024) break;
        if (info.num_extra_channels) {
          JxlExtraChannelInfo extra;
          if (JxlDecoderGetExtraChannelInfo(decoder, 0, &extra) != JXL_DEC_SUCCESS ||
              extra.type != JXL_CHANNEL_ALPHA) break;
        }
        image->width = info.xsize; image->height = info.ysize;
        image->bgra.resize((size_t)info.xsize * info.ysize * 4);
      } else if (status == JXL_DEC_NEED_IMAGE_OUT_BUFFER) {
        size_t required = 0;
        if (image->bgra.empty() ||
            JxlDecoderImageOutBufferSize(decoder, &format, &required) != JXL_DEC_SUCCESS ||
            required != image->bgra.size() ||
            JxlDecoderSetImageOutBuffer(decoder, &format, image->bgra.data(), required) != JXL_DEC_SUCCESS) break;
      } else if (status == JXL_DEC_FULL_IMAGE) {
        if (complete) break;
        complete = true;
      } else if (status == JXL_DEC_SUCCESS) {
        if (!complete) break;
        for (size_t i = 0; i < image->bgra.size(); i += 4) {
          uint8_t red = image->bgra[i]; image->bgra[i] = image->bgra[i+2]; image->bgra[i+2] = red;
        }
        ok = true; break;
      } else break;
    }
  } catch (const std::bad_alloc&) { ok = false; }
  JxlDecoderDestroy(decoder);
  if (!ok) *image = JxlDecodedImage{};
  return ok;
}
