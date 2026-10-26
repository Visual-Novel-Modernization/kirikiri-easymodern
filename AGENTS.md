# Development & Maintenance Guidelines for Agents

## Project Scope & Constraints
- **Target Game**: *すれ違う兄妹の壊れる倫理観 特典付き限定版* (CloverGAME, 32-bit krkrz engine).
- **Core Functionality**:
  - High-efficiency JXL image decoding hook for KiriKiri Z, supporting TLG0 hybrid containers with preserved `tags` chunk metadata (`jxl_hook.dll`).
  - Native AV1 `iTVPVideoOverlay` (`vomLayer`) provider integration via statically linked `libdav1d` (`av1_gst_hook.dll`), built-in ISO BMFF (`.mp4`) / `.ivf` demuxing, and Windows ACM (`msacm32`) + `waveOut` audio synchronization.
- **All documentation, code, comments, commit messages, and agent artifacts must remain strictly in English.**

## Safety & Operational Invariants
1. **Never Launch, Terminate, or Restart the Game Binary**:
   - Automated agents are strictly prohibited from spawning, killing, or controlling the game process.
   - All runtime verification and visual rendering confirmation belong exclusively to the user.
2. **Asset Preservation & Path Hygiene**:
   - Never perform destructive overwrites on original game archives (`*.xp3`) or executables.
   - All extracted assets, build artifacts, manifests, and temporary logs must reside strictly in an external workspace outside the repository.
   - Never commit machine-specific paths, usernames, credentials, binary products (`*.dll`, `*.exe`, `*.o`), archive packages (`*.xp3`), or media assets.
3. **Engine Compatibility & ASLR**:
   - All hook offsets and target addresses must be computed dynamically relative to runtime `GetModuleHandleW(NULL)`.
   - Never disable or bypass operating system ASLR.
   - Never enforce strict executable SHA-256 or digital signature checks; the hook must maintain seamless compatibility with translation patches, engine updates, and unpacked executables.
4. **Zero-Dependency Static `libdav1d` Video Backend**:
   - `av1_gst_hook.dll` statically links `libdav1d.a` and implements KiriKiri's native 74-slot `iTVPVideoOverlay` vtable (`tTVPDSLayerVideo` ABI).
   - No external GStreamer runtime or third-party codec DLLs are required.
5. **Concurrency & Workload Controls**:
   - Image conversion pipelines may utilize at most 6 parallel worker processes (`max_workers = 6`).
   - Single worker processes must avoid runaway threads to prevent memory starvation and I/O congestion.
6. **Git Identity**:
   - Repository-local identity must strictly use:
     - Name: `Cave Johnson`
     - Email: `cave.johnson@aperturescience.com`

## Technical Engine Contracts
- **PE Architecture**: 32-bit x86 PE32.
- **Hook Targets**:
  - PNG Handler RVA: `0x001AFFE0`
  - TLG Handler RVA: `0x001B1D20`
  - Engine String Constructor RVA: `0x0002A870`
  - Engine String Destructor RVA: `0x00029A80`
  - `Storages.isExistentStorage` RVA: `0x00037E40`
  - `TVPCreateDSLayerVideoOverlay` RVA: `0x00087B60`
  - `tTJSNI_VideoOverlay::Open` RVA: `0x001DD020`
  - Expected 5-byte Prologue: `55 8b ec 6a ff`
- **TLG0 Hybrid Container Layout**:
  - `TLG0.0\x00sds\x1a` (11 bytes)
  - `uint32_t raw_data_offset` (size of JXL bitstream)
  - JXL raw stream (starts with `0xFF 0x0A` or container magic)
  - SDS Chunks (e.g., `tags` chunk containing `mode`, `left`, `top`, etc.)
- **Video HandBrakeCLI Parameters**:
  - SVT-AV1, Preset 5
  - 720p: CRF 28
  - 1080p: CRF 32
  - Audio: Passthrough (`copy`)
