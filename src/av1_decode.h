#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <dav1d/dav1d.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <vector>
#include <algorithm>

struct Mp4SampleEntry {
  uint64_t offset;
  uint32_t size;
  double pts_sec;
};

struct Mp4VideoTrack {
  bool valid = false;
  uint32_t width = 0;
  uint32_t height = 0;
  uint32_t timescale = 0;
  uint64_t duration = 0;
  double fps = 29.97;
  double duration_sec = 0.0;
  std::vector<uint8_t> config_obus;
  std::vector<Mp4SampleEntry> samples;
};

struct Mp4AudioTrack {
  bool valid = false;
  uint16_t channels = 2;
  uint32_t sample_rate = 48000;
  uint16_t bits_per_sample = 16;
  uint8_t object_type_indication = 0; // 0x6B = MP3, 0x40 = AAC
  uint32_t timescale = 0;
  uint64_t duration = 0;
  std::vector<Mp4SampleEntry> samples;
};

struct Mp4ContainerInfo {
  bool valid = false;
  Mp4VideoTrack video;
  Mp4AudioTrack audio;
};

static inline uint16_t ReadBe16(const uint8_t* p) {
  return (uint16_t)((p[0] << 8) | p[1]);
}

static inline uint32_t ReadBe32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint64_t ReadBe64(const uint8_t* p) {
  return ((uint64_t)ReadBe32(p) << 32) | (uint64_t)ReadBe32(p + 4);
}

static inline bool IsAv1Mp4Header(const uint8_t* data, size_t size) {
  if (!data || size < 12) return false;
  if (memcmp(data + 4, "ftyp", 4) == 0) return true;
  if (memcmp(data, "DKIF", 4) == 0) return true;
  return false;
}

namespace detail {

struct SttsRun {
  uint32_t count;
  uint32_t delta;
};

struct StscRun {
  uint32_t first_chunk;
  uint32_t samples_per_chunk;
  uint32_t sample_desc_idx;
};

struct RawTrackTables {
  uint32_t handler_type = 0;
  uint32_t timescale = 0;
  uint64_t duration = 0;
  uint32_t width = 0;
  uint32_t height = 0;
  bool is_av01 = false;
  bool is_audio = false;
  uint16_t channels = 2;
  uint16_t bits_per_sample = 16;
  uint32_t sample_rate = 48000;
  uint8_t audio_oti = 0;
  std::vector<uint8_t> config_obus;
  std::vector<SttsRun> stts;
  std::vector<StscRun> stsc;
  uint32_t fixed_sample_size = 0;
  uint32_t sample_count = 0;
  std::vector<uint32_t> sample_sizes;
  std::vector<uint64_t> chunk_offsets;
};

static inline void ParseEsdsBox(const uint8_t* buf, size_t size, uint8_t* out_oti) {
  if (size < 6 || !out_oti) return;
  size_t pos = 4; // skip version/flags
  while (pos + 2 <= size) {
    uint8_t tag = buf[pos++];
    uint32_t len = 0;
    for (int i = 0; i < 4 && pos < size; ++i) {
      uint8_t b = buf[pos++];
      len = (len << 7) | (b & 0x7F);
      if ((b & 0x80) == 0) break;
    }
    if (tag == 0x03) { // ES_DescrTag
      if (pos + 3 > size) break;
      pos += 2; // ES_ID
      uint8_t flags = buf[pos++];
      if (flags & 0x80) pos += 2;
      if (flags & 0x40) {
        if (pos < size) pos += 1 + buf[pos];
      }
      if (flags & 0x20) pos += 2;
    } else if (tag == 0x04) { // DecoderConfigDescrTag
      if (pos < size) {
        *out_oti = buf[pos];
      }
      return;
    } else {
      pos += len;
    }
  }
}

static inline void ParseStblSubBoxes(const uint8_t* base, size_t file_size,
                                     size_t start, size_t end, RawTrackTables* trk) {
  size_t pos = start;
  while (pos + 8 <= end && pos + 8 <= file_size) {
    uint64_t sz = ReadBe32(base + pos);
    uint32_t typ = ReadBe32(base + pos + 4);
    size_t hdr = 8;
    if (sz == 1) {
      if (pos + 16 > end) break;
      sz = ReadBe64(base + pos + 8);
      hdr = 16;
    } else if (sz == 0) {
      sz = end - pos;
    }
    if (sz < hdr || pos + sz > end || pos + sz > file_size) break;
    const uint8_t* body = base + pos + hdr;
    size_t body_sz = (size_t)(sz - hdr);

    if (typ == 0x73747364) { // 'stsd'
      if (body_sz >= 8) {
        uint32_t entries = ReadBe32(body + 4);
        size_t p2 = 8;
        for (uint32_t i = 0; i < entries && p2 + 8 <= body_sz; ++i) {
          uint32_t esz = ReadBe32(body + p2);
          uint32_t etyp = ReadBe32(body + p2 + 4);
          if (esz < 8 || p2 + esz > body_sz) break;
          if (etyp == 0x61763031 && esz >= 86) { // 'av01'
            trk->is_av01 = true;
            trk->width = ReadBe16(body + p2 + 32);
            trk->height = ReadBe16(body + p2 + 34);
            // Parse child boxes inside av01 sample entry (offset 86)
            size_t p3 = p2 + 86;
            size_t end3 = p2 + esz;
            while (p3 + 8 <= end3) {
              uint32_t csz = ReadBe32(body + p3);
              uint32_t ctyp = ReadBe32(body + p3 + 4);
              if (csz < 8 || p3 + csz > end3) break;
              if (ctyp == 0x61763143 && csz > 12) { // 'av1C'
                // Skip 4-byte av1C header to get configOBUs
                size_t obu_len = csz - 12;
                trk->config_obus.assign(body + p3 + 12, body + p3 + 12 + obu_len);
              }
              p3 += csz;
            }
          } else if ((etyp == 0x6D703461 || etyp == 0x2E6D7033) && esz >= 36) { // 'mp4a' or '.mp3'
            trk->is_audio = true;
            trk->channels = ReadBe16(body + p2 + 24);
            trk->bits_per_sample = ReadBe16(body + p2 + 26);
            trk->sample_rate = ReadBe32(body + p2 + 32) >> 16;
            if (etyp == 0x2E6D7033) trk->audio_oti = 0x6B;
            size_t p3 = p2 + 36;
            size_t end3 = p2 + esz;
            while (p3 + 8 <= end3) {
              uint32_t csz = ReadBe32(body + p3);
              uint32_t ctyp = ReadBe32(body + p3 + 4);
              if (csz < 8 || p3 + csz > end3) break;
              if (ctyp == 0x65736473) { // 'esds'
                ParseEsdsBox(body + p3 + 8, csz - 8, &trk->audio_oti);
              }
              p3 += csz;
            }
          }
          p2 += esz;
        }
      }
    } else if (typ == 0x73747473) { // 'stts'
      if (body_sz >= 8) {
        uint32_t cnt = ReadBe32(body + 4);
        if (8 + (uint64_t)cnt * 8 <= body_sz) {
          trk->stts.resize(cnt);
          for (uint32_t i = 0; i < cnt; ++i) {
            trk->stts[i].count = ReadBe32(body + 8 + i * 8);
            trk->stts[i].delta = ReadBe32(body + 12 + i * 8);
          }
        }
      }
    } else if (typ == 0x73747363) { // 'stsc'
      if (body_sz >= 8) {
        uint32_t cnt = ReadBe32(body + 4);
        if (8 + (uint64_t)cnt * 12 <= body_sz) {
          trk->stsc.resize(cnt);
          for (uint32_t i = 0; i < cnt; ++i) {
            trk->stsc[i].first_chunk = ReadBe32(body + 8 + i * 12);
            trk->stsc[i].samples_per_chunk = ReadBe32(body + 12 + i * 12);
            trk->stsc[i].sample_desc_idx = ReadBe32(body + 16 + i * 12);
          }
        }
      }
    } else if (typ == 0x7374737A) { // 'stsz'
      if (body_sz >= 12) {
        trk->fixed_sample_size = ReadBe32(body + 4);
        trk->sample_count = ReadBe32(body + 8);
        if (trk->fixed_sample_size == 0 && 12 + (uint64_t)trk->sample_count * 4 <= body_sz) {
          trk->sample_sizes.resize(trk->sample_count);
          for (uint32_t i = 0; i < trk->sample_count; ++i) {
            trk->sample_sizes[i] = ReadBe32(body + 12 + i * 4);
          }
        }
      }
    } else if (typ == 0x7374636F) { // 'stco'
      if (body_sz >= 8) {
        uint32_t cnt = ReadBe32(body + 4);
        if (8 + (uint64_t)cnt * 4 <= body_sz) {
          trk->chunk_offsets.resize(cnt);
          for (uint32_t i = 0; i < cnt; ++i) {
            trk->chunk_offsets[i] = ReadBe32(body + 8 + i * 4);
          }
        }
      }
    } else if (typ == 0x636F3634) { // 'co64'
      if (body_sz >= 8) {
        uint32_t cnt = ReadBe32(body + 4);
        if (8 + (uint64_t)cnt * 8 <= body_sz) {
          trk->chunk_offsets.resize(cnt);
          for (uint32_t i = 0; i < cnt; ++i) {
            trk->chunk_offsets[i] = ReadBe64(body + 8 + i * 8);
          }
        }
      }
    }
    pos += (size_t)sz;
  }
}

static inline void ParseTrakBoxes(const uint8_t* base, size_t file_size,
                                  size_t start, size_t end, RawTrackTables* trk) {
  size_t pos = start;
  while (pos + 8 <= end && pos + 8 <= file_size) {
    uint64_t sz = ReadBe32(base + pos);
    uint32_t typ = ReadBe32(base + pos + 4);
    size_t hdr = 8;
    if (sz == 1) {
      if (pos + 16 > end) break;
      sz = ReadBe64(base + pos + 8);
      hdr = 16;
    } else if (sz == 0) {
      sz = end - pos;
    }
    if (sz < hdr || pos + sz > end || pos + sz > file_size) break;
    const uint8_t* body = base + pos + hdr;
    size_t body_sz = (size_t)(sz - hdr);

    if (typ == 0x6D646961 || typ == 0x6D696E66) { // 'mdia', 'minf'
      ParseTrakBoxes(base, file_size, pos + hdr, pos + (size_t)sz, trk);
    } else if (typ == 0x7374626C) { // 'stbl'
      ParseStblSubBoxes(base, file_size, pos + hdr, pos + (size_t)sz, trk);
    } else if (typ == 0x6D646864) { // 'mdhd'
      if (body_sz >= 20) {
        uint8_t ver = body[0];
        if (ver == 0) {
          trk->timescale = ReadBe32(body + 12);
          trk->duration = ReadBe32(body + 16);
        } else if (body_sz >= 32) {
          trk->timescale = ReadBe32(body + 20);
          trk->duration = ReadBe64(body + 24);
        }
      }
    } else if (typ == 0x68646C72) { // 'hdlr'
      if (body_sz >= 12) {
        trk->handler_type = ReadBe32(body + 8);
      }
    }
    pos += (size_t)sz;
  }
}

static inline bool BuildTrackSamples(const RawTrackTables& trk, size_t file_size,
                                     std::vector<Mp4SampleEntry>* out_samples) {
  if (!out_samples || trk.sample_count == 0 || trk.chunk_offsets.empty() || trk.stsc.empty()) {
    return false;
  }
  out_samples->clear();
  out_samples->reserve(trk.sample_count);

  double inv_ts = (trk.timescale > 0) ? (1.0 / (double)trk.timescale) : (1.0 / 90000.0);
  size_t stts_idx = 0;
  uint32_t stts_rem = trk.stts.empty() ? 0 : trk.stts[0].count;
  uint64_t cur_dts = 0;

  uint32_t sample_idx = 0;
  uint32_t total_chunks = (uint32_t)trk.chunk_offsets.size();
  size_t stsc_idx = 0;

  for (uint32_t chunk_1based = 1; chunk_1based <= total_chunks && sample_idx < trk.sample_count; ++chunk_1based) {
    while (stsc_idx + 1 < trk.stsc.size() && trk.stsc[stsc_idx + 1].first_chunk <= chunk_1based) {
      ++stsc_idx;
    }
    uint32_t spc = trk.stsc[stsc_idx].samples_per_chunk;
    uint64_t offset = trk.chunk_offsets[chunk_1based - 1];

    for (uint32_t s = 0; s < spc && sample_idx < trk.sample_count; ++s) {
      uint32_t sz = (trk.fixed_sample_size != 0) ? trk.fixed_sample_size : trk.sample_sizes[sample_idx];
      if (offset + sz > file_size) return false;

      Mp4SampleEntry entry;
      entry.offset = offset;
      entry.size = sz;
      entry.pts_sec = (double)cur_dts * inv_ts;
      out_samples->push_back(entry);

      offset += sz;
      ++sample_idx;

      if (!trk.stts.empty()) {
        cur_dts += trk.stts[stts_idx].delta;
        if (stts_rem > 0 && --stts_rem == 0 && stts_idx + 1 < trk.stts.size()) {
          ++stts_idx;
          stts_rem = trk.stts[stts_idx].count;
        }
      }
    }
  }
  return !out_samples->empty();
}

} // namespace detail

static inline bool ParseMp4Container(const uint8_t* data, size_t size, Mp4ContainerInfo* out_info) {
  if (!data || size < 32 || !out_info) return false;
  *out_info = Mp4ContainerInfo();

  // Check for IVF container first ("DKIF")
  if (memcmp(data, "DKIF", 4) == 0 && size >= 32) {
    uint16_t w = (uint16_t)(data[12] | (data[13] << 8));
    uint16_t h = (uint16_t)(data[14] | (data[15] << 8));
    uint32_t fps_num = (uint32_t)data[16] | ((uint32_t)data[17] << 8) | ((uint32_t)data[18] << 16) | ((uint32_t)data[19] << 24);
    uint32_t fps_den = (uint32_t)data[20] | ((uint32_t)data[21] << 8) | ((uint32_t)data[22] << 16) | ((uint32_t)data[23] << 24);
    if (!w || !h) return false;
    out_info->video.valid = true;
    out_info->video.width = w;
    out_info->video.height = h;
    out_info->video.fps = (fps_num > 0 && fps_den > 0) ? ((double)fps_num / (double)fps_den) : 29.97;
    size_t pos = 32;
    uint32_t idx = 0;
    while (pos + 12 <= size) {
      uint32_t fsz = (uint32_t)data[pos] | ((uint32_t)data[pos + 1] << 8) |
                     ((uint32_t)data[pos + 2] << 16) | ((uint32_t)data[pos + 3] << 24);
      if (pos + 12 + fsz > size) break;
      Mp4SampleEntry e;
      e.offset = pos + 12;
      e.size = fsz;
      e.pts_sec = (double)idx / out_info->video.fps;
      out_info->video.samples.push_back(e);
      pos += 12 + fsz;
      ++idx;
    }
    out_info->video.duration_sec = (double)out_info->video.samples.size() / out_info->video.fps;
    out_info->valid = !out_info->video.samples.empty();
    return out_info->valid;
  }

  size_t pos = 0;
  while (pos + 8 <= size) {
    uint64_t sz = ReadBe32(data + pos);
    uint32_t typ = ReadBe32(data + pos + 4);
    size_t hdr = 8;
    if (sz == 1) {
      if (pos + 16 > size) break;
      sz = ReadBe64(data + pos + 8);
      hdr = 16;
    } else if (sz == 0) {
      sz = size - pos;
    }
    if (sz < hdr || pos + sz > size) break;

    if (typ == 0x6D6F6F76) { // 'moov'
      size_t mpos = pos + hdr;
      size_t mend = pos + (size_t)sz;
      while (mpos + 8 <= mend) {
        uint64_t tsz = ReadBe32(data + mpos);
        uint32_t ttyp = ReadBe32(data + mpos + 4);
        size_t thdr = 8;
        if (tsz == 1) {
          if (mpos + 16 > mend) break;
          tsz = ReadBe64(data + mpos + 8);
          thdr = 16;
        } else if (tsz == 0) {
          tsz = mend - mpos;
        }
        if (tsz < thdr || mpos + tsz > mend) break;

        if (ttyp == 0x7472616B) { // 'trak'
          detail::RawTrackTables trk;
          detail::ParseTrakBoxes(data, size, mpos + thdr, mpos + (size_t)tsz, &trk);
          if (trk.handler_type == 0x76696465 && trk.is_av01 && trk.width > 0 && trk.height > 0) { // 'vide'
            if (detail::BuildTrackSamples(trk, size, &out_info->video.samples)) {
              out_info->video.valid = true;
              out_info->video.width = trk.width;
              out_info->video.height = trk.height;
              out_info->video.timescale = trk.timescale;
              out_info->video.duration = trk.duration;
              out_info->video.config_obus = std::move(trk.config_obus);
              if (trk.timescale > 0 && trk.duration > 0) {
                out_info->video.duration_sec = (double)trk.duration / (double)trk.timescale;
                if (out_info->video.samples.size() > 1) {
                  out_info->video.fps = (double)out_info->video.samples.size() / out_info->video.duration_sec;
                }
              }
            }
          } else if (trk.handler_type == 0x736F756E && trk.is_audio) { // 'soun'
            if (detail::BuildTrackSamples(trk, size, &out_info->audio.samples)) {
              out_info->audio.valid = true;
              out_info->audio.channels = trk.channels ? trk.channels : 2;
              out_info->audio.sample_rate = trk.sample_rate ? trk.sample_rate : 48000;
              out_info->audio.bits_per_sample = trk.bits_per_sample ? trk.bits_per_sample : 16;
              out_info->audio.object_type_indication = trk.audio_oti;
              out_info->audio.timescale = trk.timescale;
              out_info->audio.duration = trk.duration;
            }
          }
        }
        mpos += (size_t)tsz;
      }
    }
    pos += (size_t)sz;
  }

  out_info->valid = out_info->video.valid && !out_info->video.samples.empty();
  return out_info->valid;
}

static inline uint8_t ClampU8(int v) {
  return (uint8_t)(v < 0 ? 0 : (v > 255 ? 255 : v));
}

// Convert Dav1dPicture (8-bit or 10-bit YUV420/422/444/400) into 32-bit BGRA buffer.
// When bottom_up is true (KiriKiri tTVPBaseBitmap layout), video row y (0 = top) is written to
// dst_bgra + (height - 1 - y) * (width * 4).
static inline bool ConvertDav1dPictureToBgra(const Dav1dPicture* pic, uint8_t* dst_bgra,
                                             uint32_t dst_width, uint32_t dst_height,
                                             bool bottom_up = true) {
  if (!pic || !dst_bgra || !pic->data[0]) return false;
  uint32_t w = (uint32_t)pic->p.w < dst_width ? (uint32_t)pic->p.w : dst_width;
  uint32_t h = (uint32_t)pic->p.h < dst_height ? (uint32_t)pic->p.h : dst_height;
  if (!w || !h) return false;

  const int bpc = pic->p.bpc;
  const int shift = (bpc > 8) ? (bpc - 8) : 0;
  const ptrdiff_t y_stride = pic->stride[0];
  const ptrdiff_t uv_stride = pic->stride[1];
  const uint8_t* y_plane = (const uint8_t*)pic->data[0];
  const uint8_t* u_plane = (const uint8_t*)pic->data[1];
  const uint8_t* v_plane = (const uint8_t*)pic->data[2];
  const size_t dst_pitch = (size_t)dst_width * 4;

  // BT.709 limited-range YUV to RGB integer coefficients (256-scale)
  // R = (298*(Y-16) + 459*(V-128) + 128) >> 8
  // G = (298*(Y-16) - 55*(U-128) - 136*(V-128) + 128) >> 8
  // B = (298*(Y-16) + 541*(U-128) + 128) >> 8
  if (pic->p.layout == DAV1D_PIXEL_LAYOUT_I420 && bpc == 8 && u_plane && v_plane) {
    uint32_t w_even = w & ~1u;
    uint32_t h_even = h & ~1u;
    for (uint32_t y = 0; y < h_even; y += 2) {
      const uint8_t* y_row0 = y_plane + (ptrdiff_t)y * y_stride;
      const uint8_t* y_row1 = y_row0 + y_stride;
      const uint8_t* u_row = u_plane + (ptrdiff_t)(y >> 1) * uv_stride;
      const uint8_t* v_row = v_plane + (ptrdiff_t)(y >> 1) * uv_stride;

      uint8_t* d_row0 = dst_bgra + (size_t)(bottom_up ? (dst_height - 1 - y) : y) * dst_pitch;
      uint8_t* d_row1 = dst_bgra + (size_t)(bottom_up ? (dst_height - 2 - y) : (y + 1)) * dst_pitch;

      for (uint32_t x = 0; x < w_even; x += 2) {
        int u = (int)u_row[x >> 1] - 128;
        int v = (int)v_row[x >> 1] - 128;
        int c_r = 459 * v + 128;
        int c_g = -55 * u - 136 * v + 128;
        int c_b = 541 * u + 128;

        int y00 = 298 * ((int)y_row0[x] - 16);
        d_row0[x * 4 + 0] = ClampU8((y00 + c_b) >> 8);
        d_row0[x * 4 + 1] = ClampU8((y00 + c_g) >> 8);
        d_row0[x * 4 + 2] = ClampU8((y00 + c_r) >> 8);
        d_row0[x * 4 + 3] = 0xFF;

        int y01 = 298 * ((int)y_row0[x + 1] - 16);
        d_row0[(x + 1) * 4 + 0] = ClampU8((y01 + c_b) >> 8);
        d_row0[(x + 1) * 4 + 1] = ClampU8((y01 + c_g) >> 8);
        d_row0[(x + 1) * 4 + 2] = ClampU8((y01 + c_r) >> 8);
        d_row0[(x + 1) * 4 + 3] = 0xFF;

        int y10 = 298 * ((int)y_row1[x] - 16);
        d_row1[x * 4 + 0] = ClampU8((y10 + c_b) >> 8);
        d_row1[x * 4 + 1] = ClampU8((y10 + c_g) >> 8);
        d_row1[x * 4 + 2] = ClampU8((y10 + c_r) >> 8);
        d_row1[x * 4 + 3] = 0xFF;

        int y11 = 298 * ((int)y_row1[x + 1] - 16);
        d_row1[(x + 1) * 4 + 0] = ClampU8((y11 + c_b) >> 8);
        d_row1[(x + 1) * 4 + 1] = ClampU8((y11 + c_g) >> 8);
        d_row1[(x + 1) * 4 + 2] = ClampU8((y11 + c_r) >> 8);
        d_row1[(x + 1) * 4 + 3] = 0xFF;
      }
    }
    return true;
  }

  // Generic path for 10-bit or I422/I444/I400
  int ss_x = (pic->p.layout == DAV1D_PIXEL_LAYOUT_I420 || pic->p.layout == DAV1D_PIXEL_LAYOUT_I422) ? 1 : 0;
  int ss_y = (pic->p.layout == DAV1D_PIXEL_LAYOUT_I420) ? 1 : 0;
  for (uint32_t y = 0; y < h; ++y) {
    uint8_t* d_row = dst_bgra + (size_t)(bottom_up ? (dst_height - 1 - y) : y) * dst_pitch;
    const uint8_t* y_line = y_plane + (ptrdiff_t)y * y_stride;
    const uint8_t* u_line = u_plane ? (u_plane + (ptrdiff_t)(y >> ss_y) * uv_stride) : nullptr;
    const uint8_t* v_line = v_plane ? (v_plane + (ptrdiff_t)(y >> ss_y) * uv_stride) : nullptr;
    for (uint32_t x = 0; x < w; ++x) {
      int y_val = (bpc == 8) ? y_line[x] : (((const uint16_t*)y_line)[x] >> shift);
      int u_val = 128, v_val = 128;
      if (u_line && v_line) {
        u_val = (bpc == 8) ? u_line[x >> ss_x] : (((const uint16_t*)u_line)[x >> ss_x] >> shift);
        v_val = (bpc == 8) ? v_line[x >> ss_x] : (((const uint16_t*)v_line)[x >> ss_x] >> shift);
      }
      int c = 298 * (y_val - 16);
      int d = u_val - 128;
      int e = v_val - 128;
      d_row[x * 4 + 0] = ClampU8((c + 541 * d + 128) >> 8);
      d_row[x * 4 + 1] = ClampU8((c - 55 * d - 136 * e + 128) >> 8);
      d_row[x * 4 + 2] = ClampU8((c + 459 * e + 128) >> 8);
      d_row[x * 4 + 3] = 0xFF;
    }
  }
  return true;
}
