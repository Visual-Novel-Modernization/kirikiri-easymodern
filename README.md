# KiriKiri Z (32-bit krkrz) JXL and AV1 Recompression & Plugin Toolkit

This repository provides an end-to-end modernization toolkit for the 32-bit KiriKiri Z (krkrz) visual novel engine (*すれ違う兄妹の壊れる倫理観*), enabling high-performance JPEG XL (JXL) image decoding and AV1 video playback via dynamic plugin hooks.

---

## 1. Key Features & Architectural Overview

- **TLG0-JXL Hybrid Container (Scheme A)**:
  - Preserves standard KiriKiri `TLG0.0\x00sds\x1a` compound container headers and internal `tags` chunk data.
  - Retains all sprite positioning metadata (`left`, `top`, `layer_type`, `mode=alpha`), preventing visual displacement ("flying head", sprite offset) or dark transparent borders.
  - Supports both 32-bit BGRA (`mode == 0`) and 8-bit grayscale/mask (`mode != 0`) scanline delivery.
  - Swaps raw TLG5/TLG6 pixel streams with compact, losslessly-alphad JXL streams (`quality 90, effort 8, --alpha_distance=0`).
- **Dynamic In-Memory Hook Architecture**:
  - Dynamically calculates target addresses based on runtime module base (`GetModuleHandleW(NULL) + target_rva`).
  - Preserves Address Space Layout Randomization (ASLR).
  - Strictly omits executable SHA-256 / signature hashes, ensuring 100% compatibility with fan translation patches, engine updates, and modified EXEs.
  - Verifies function prologues (`55 8b ec 6a ff`) prior to atomic detour installation.
- **Native `iTVPVideoOverlay` AV1 Video Backend via Statically Linked `libdav1d`**:
  - Implements KiriKiri's native 74-slot `iTVPVideoOverlay` C++ interface (`tTVPDSLayerVideo` ABI) inside `av1_gst_hook.dll`.
  - Statically links `libdav1d` for fast multi-threaded AV1 decoding directly into KiriKiri's double-buffered `tTVPBaseBitmap` layer surfaces (`vomLayer` mode).
  - Includes a self-contained ISO BMFF (`.mp4`) and `.ivf` demuxer and synchronizes video presentation to hardware audio playback via Windows ACM (`msacm32.dll`) and `waveOut`.
  - Requires zero external GStreamer runtimes or third-party codec installers.
- **Scalable 6-Worker Processing Pipeline**:
  - Python multi-process conversion pipeline operating across 6 concurrent workers with isolated workspaces.
  - Automated detection and preservation of semantics-sensitive UI controls, transition masks, and thumbnail images.

---

## 2. MSYS2 Toolchain & Dependency Setup

Because the target KiriKiri Z engine is a 32-bit (`i686` PE32) executable, all plugin DLLs and static libraries must be built with the 32-bit **MSYS2 MINGW32** (`mingw-w64-i686`) environment.

### Step 1: Install 32-bit Compiler and Static Libraries via `pacman`
Open an **MSYS2 MSYS** or **MSYS2 MINGW32** shell and synchronize the package database, then install the 32-bit GCC toolchain, `libjxl`, `dav1d`, `brotli`, `highway`, and `winpthreads`:

```bash
pacman -Syu
pacman -S --needed \
  mingw-w64-i686-gcc \
  mingw-w64-i686-libjxl \
  mingw-w64-i686-dav1d \
  mingw-w64-i686-brotli \
  mingw-w64-i686-highway \
  mingw-w64-i686-winpthreads-git
```

### Step 2: Verify Installed Static Archives and Headers
Confirm that the following headers and static archives exist under your `<msys64>/mingw32` prefix:
- `include/jxl/decode.h` and `lib/libjxl.a`, `lib/libjxl_cms.a`
- `include/dav1d/dav1d.h` and `lib/libdav1d.a`
- `lib/libbrotlidec.a`, `lib/libbrotlicommon.a`, `lib/libhwy.a`, `lib/libwinpthread.a`
- `bin/libwinpthread-1.dll`

---

## 3. Build Instructions

Set `MINGW32_ROOT` to your 32-bit MSYS2 `mingw32` directory and run `build.ps1` in PowerShell:

```powershell
$env:MINGW32_ROOT = "C:\msys64\mingw32"
.\build.ps1 -ToolchainRoot $env:MINGW32_ROOT -OutDir ".\bin"
```

### Deliverables Output:
- `bin/jxl_hook.dll`: 32-bit KiriKiri image hook plugin (exports `V2Link`, `V2Unlink`, `JxlHookVersion`).
- `bin/av1_gst_hook.dll`: 32-bit KiriKiri AV1 `iTVPVideoOverlay` provider plugin with statically linked `libdav1d` (exports `V2Link`, `V2Unlink`, `GetActiveAv1Decoder`).
- `bin/hook_selftest.exe`: Standalone console validation harness for both JXL and AV1 decoding.
- `bin/libwinpthread-1.dll`: Dependent MinGW runtime library.

---

## 4. Resource Conversion & Packaging Workflow

All intermediate assets and caches must strictly reside in external workspaces (`$env:WORK_DIR`).

### Step 1: Unpack Target Archive
```powershell
xp3brute unpack "$env:WORK_DIR\char.xp3" "$env:WORK_DIR\unpacked_char" --tlg none --no-progress
```

### Step 2: Batch Compress Images (6 Workers)
```powershell
python tools/pipeline.py compress-images `
  --in-dir "$env:WORK_DIR\unpacked_char" `
  --out-dir "$env:WORK_DIR\compressed_char" `
  --workers 6
```

### Step 3: Transcode Opening & Effect Videos to AV1
```powershell
# 1080p: CRF 32, Preset 5 | 720p: CRF 28, Preset 5
python tools/pipeline.py compress-video `
  --input "$env:WORK_DIR\unpacked_parts\sureimo.mpg" `
  --output "$env:WORK_DIR\output\sureimo_av1.mp4" `
  --height 1080
```

### Step 4: Inject Plugin Loading into Startup Script
Add the standard plugin loading calls to the beginning of `startup.tjs`:
```javascript
Plugins.link("jxl_hook.dll");
Plugins.link("av1_gst_hook.dll");
```

### Step 5: Repack into XP3 Archive
```powershell
xp3brute pack "$env:WORK_DIR\compressed_char" "$env:WORK_DIR\output\char.xp3" `
  --source-archive "$env:WORK_DIR\char.xp3" `
  --compact-layout
```

---

## 5. Verification & Testing Protocol

- **Offline Self-Test**:
  ```powershell
  .\bin\hook_selftest.exe --version
  .\bin\hook_selftest.exe --bgra sample.jxl sample.bgra
  .\bin\hook_selftest.exe --av1-info sample_av1.mp4
  ```
- **Manual Game Verification Checklist**:
  1. Confirm character sprites render with proper offsets (head and body aligned).
  2. Confirm transparent gradient edges render smoothly without black background artifacts.
  3. Verify movie playback functions properly during opening scene and recollection playback via `libdav1d` layer rendering.
  4. Verify game saves and loads without corruption.

---

## 6. Backup & Rollback Strategy

1. Maintain pristine copies of original `*.xp3` archives outside the game folder before applying modifications.
2. To rollback:
   - Remove `jxl_hook.dll`, `av1_gst_hook.dll`, and `libwinpthread-1.dll` from `<GameDir>/plugin/`.
   - Restore the original `data.xp3`, `char.xp3`, `event.xp3`, and `parts.xp3` from external backups.
