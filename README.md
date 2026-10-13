# ISLAND DIARY JXL Hook

An exact-build Windows x86 plugin for ISLAND DIARY. Selected PNG archive entries retain their original paths and extensions while carrying JPEG XL payloads. Ordinary PNG streams use the original engine decoder. The repository distributes source only; game resources and runtime evidence remain external.

## Supported executable

| Property | Required value |
| --- | --- |
| File description | ISLAND DIARY |
| Engine file/product version | KiriKiri Z 1.2.0.3 |
| Architecture | PE32 i386 |
| Executable SHA-256 | `9b7733355d5b717d38a45c32148041f0e08462a0ca11844854fbec15dbad6b93` |
| PNG handler RVA | `0x123B10` |
| Replaced instructions | `55 8B EC 6A FF` (`push ebp; mov ebp,esp; push -1`) |

The DLL checks the executable hash, PE headers, and handler bytes before installing a five-byte detour. The address is the actual loaded module base plus the RVA. The trampoline copies three complete instructions and resumes at module base plus `0x123B15`. ASLR remains enabled. Installation must occur during startup before concurrent image decoding; dynamic unload is refused.

Independent disassembly of this executable established the PNG registry assignment at RVA `0xE9F09` for UTF-16 `.png`, the indirect handler call at `0xEC4AB`, and caller cleanup of eight stack arguments at `0xEC4AD`. The handler is `__cdecl(formatdata, callbackdata, size, scanline, metadata, stream, keyidx, mode)`. Stream seek and read are virtual slots 0 and 1 using `__cdecl` with explicit stack self. The stream destructor uses a different convention and is never called by the hook. Size and scanline callbacks use caller cleanup; each copied row is followed by scanline callback `-1`. Metadata arguments are string wrapper references. These properties were verified for this executable even where they match other builds.

## Build

Install an i686 MinGW-w64 C++17 toolchain with compatible static libjxl, libjxl CMS, Brotli decoder/common, Highway, and winpthread libraries. Set the toolchain location and an external build directory:

```powershell
./build.ps1 -ToolchainRoot $env:MINGW32_ROOT -OutDir $env:JXL_BUILD
```

This builds `island_jxl_hook.dll`, `hook_selftest.exe`, and the matching `libwinpthread-1.dll`. Build output inside the repository is rejected. The decoder and reference 32-bit `djxl` must have the same version; initial validation used libjxl 0.11.1 and cjxl 0.12.0. Dependency licenses are in `LICENSES/`.

## Isolated verification

```powershell
& "$env:JXL_BUILD/hook_selftest.exe" --version
& "$env:JXL_BUILD/hook_selftest.exe" --bgra sample.jxl sample.bgra --hook "$env:JXL_BUILD/island_jxl_hook.dll"
```

The selftest loads the actual DLL and exercises its handler using a synthetic stream and strict callbacks, including short reads, stream restoration, invalid payload rejection, and ordinary PNG fallback. It emits payload and callback-output hashes. This proves the tested DLL's decode and callback path in isolation. It does not prove detour installation or rendering inside a running engine; those require a user-operated game test.

## Conversion and archive verification

Python 3.10+, Pillow, and NumPy are required. Keep original archives, extracted files, conversion work, manifests, outputs, logs, and release binaries outside the repository. Original protected XP3 resources must be recovered without derived asset conversion and validated against the declared original Adler32 before use. Source audit records original archive and stored-segment hashes as well as recovered source SHA-256. Never treat raw encrypted extraction as a decoded source.

After recovery, audit each archive with its exact recovered tree and extractor provenance:

```powershell
python tools/xp3.py audit --archive "$env:JXL_ORIGINAL/data.xp3" --extracted "$env:JXL_RECOVERED/data" --extractor $env:XP3_EXTRACTOR --report "$env:JXL_WORK/data-source.json"
python tools/xp3.py audit --archive "$env:JXL_ORIGINAL/adult.xp3" --extracted "$env:JXL_RECOVERED/adult" --extractor $env:XP3_EXTRACTOR --report "$env:JXL_WORK/adult-source.json"
$common = @('--work', $env:JXL_WORK, '--audit', "$env:JXL_WORK/data-source.json", '--audit', "$env:JXL_WORK/adult-source.json", '--cjxl', $env:CJXL, '--workers', '3', '--threads', '4')
python tools/pipeline.py scan @common
python tools/pipeline.py convert @common
$native = @('--hook', "$env:JXL_BUILD/island_jxl_hook.dll", '--selftest', "$env:JXL_BUILD/hook_selftest.exe", '--djxl-x86', $env:DJXL_X86)
python tools/pipeline.py native @common @native
python tools/pipeline.py build @common @native --output $env:JXL_OUTPUT
python tools/pipeline.py verify @common @native --output $env:JXL_OUTPUT
```

GARbro's bundled scheme database explicitly maps `IslandDiary.exe` to `Island Diary` and selects `CxEncryption` (mask `0x1E8`, offset `0x78`, embedded control block). Use this existing scheme for recovery. GARbro's normal entry extraction also decodes certain obfuscated text scripts; those normalized outputs fail the exact source-size/Adler audit. Recover the Cx-decrypted payload before `ICrypt.EntryReadFilter` postprocessing for byte-preserving rebuilds. The official implementation passes original Adler checks for background, CG, and compiled startup samples; the full recovered inventory must pass the audit before conversion.

These environment variables are explicit user-selected tool and external directory locations. Builds refuse to overwrite existing archives. An exact identified invalid warning decoy is reported and excluded from the logical resource inventory; ordinary files receive strict validation.

Conversion uses quality 90, effort 8, and alpha distance 0, at most three workers and four threads per tool, with one process holding the conversion lock. Only beneficial supported RGB/RGBA PNG payloads are retained. Backgrounds and CG are preferred. Rule, mask, UI, thumbnail, palette, grayscale, high-depth, and animated images stay original, as do TLG, scripts, fonts, sound, and video. A candidate must beat the original stored resource cost.

Native verification is tied to the current manifest key, source and payload hashes, conversion configuration, hook binary, selftest binary, and matching 32-bit djxl binary/version. It checks source alpha exactly and compares callback BGRA byte for byte against the matching reference decoder. Archive construction rejects missing or stale evidence and validates index, segment ranges, safe paths, Adler32, exact inventory, and per-entry SHA-256 after writing.

## Loading, manual testing, and recovery

This game's original `startup.tjs` is compiled `TJS2100` bytecode. Static decompilation shows it sets the packed/debug globals and calls `Scripts.execStorage('system/Initialize.tjs')`; it does not load plugins itself. Preserve that original bytecode rather than reconstructing its getter declarations from decompiler output. Prepare physical startup files:

```powershell
python tools/prepare_startup_files.py --startup "$env:JXL_RECOVERED/data/startup.tjs" --output $env:JXL_OUTPUT
```

The optional `prepare_startup.py` plain XP3 sidecar is a diagnostic artifact and is not part of the deployment package.

For the physical startup route, use `python tools/prepare_startup_files.py --startup "$env:JXL_RECOVERED/data/startup.tjs" --output $env:JXL_OUTPUT`. It creates a UTF-16 wrapper and the exact original bytecode as separate physical files. It uses `System.exePath` for the DLL and original script paths, so both must be installed beside the EXE. Supply an explicit `-startup=file://./<drive>/<path>/island_jxl_startup.tjs` argument when launching manually. The source inventory passed 4,202 data entries and 1,035 adult entries. The completed batch converted 173 data and 225 adult images; all 398 passed exact DLL/djxl BGRA and source alpha validation. Built plaintext archives contain exactly the original inventory with converted payloads substituted, and retain the original `startup.tjs` unchanged. Live game testing has not been performed.

The archive wrapper calls `Plugins.link("island_jxl_hook.dll")` synchronously before `Scripts.execStorage("island_jxl_original_startup.tjs")`. The sidecar contains the original compiled startup unchanged under that unique storage name. Its original SHA-256 for this build is `25fbd9f90fa7e7a783b1c4485b86e0004257dc056475623ef79bd11a304d0cf5`. This two-entry plain sidecar is a preparation artifact. It cannot serve as an archive bootstrap while the original Cx filter remains registered. Exact-build static evidence: XP3 reader VA `0x437700` checks only global VA `0x7B82C0` at `0x4377F6` and invokes it at `0x43783A`; the parser at `0x436050` does not use the info protection flag. The filter setter is `__stdcall` VA `0x41DBA0`. After successful validated detour installation, the hook clears that global at actual module base plus RVA `0x3B82C0`. This transition requires the wrapper to have already been loaded through the original encrypted filter or directly from physical storage. Do not deploy the plain sidecar as an unverified replacement. A physical wrapper selected with an explicit `-startup` argument avoids archive precedence: the UTF-16 `-startup` option at VA `0x6F05D8` is parsed at `0x40750E` and stored in startup global `0x7BC058`; the startup runner at `0x408C00` executes that storage. The file media at `0x424790` returns `file`, `0x4248D0` opens its stream, native absolute drive paths are normalized at `0x424EF0`, and local stream constructor `0x4259C0` calls `CreateFileW` at `0x425A76`. Supply the wrapper as explicit physical storage (`file://./<drive>/<path>/island_jxl_startup.tjs`) when manually launching. This establishes static loader behavior; live execution still requires user verification. The plugin must be loaded using this game's verified startup mechanism before image decoding. The hook log is `island_jxl_hook.log` beside the executable. The isolated selftest also checks that `V2Link` refuses an executable whose SHA-256 does not match. Keep the original startup script and archive files intact; use separately prepared output and a reversible manual deployment. Do not edit or load a startup script copied from another game.

The user must launch and close the game manually. Check the hook log for an installed detour with the actual module base and JXL payload hashes, then test title/menu behavior, backgrounds, CG, transitions, transparency, gallery thumbnails, saving, and loading. Synthetic and archive verification alone do not establish visual correctness. Keep work caches and verification reports until this test succeeds.

To restore, close the game manually, remove the startup hook-loading addition and plugin dependency files, and restore the preserved original archives. Do not delete the original backups.

## Limitations

Only normal mode 0 with default key index -1 and eight-bit BGRA is supported. Metadata callbacks and alternate color-key/palette/grayscale behavior are not reproduced; resources requiring them must retain PNG. Animated JXL, nonidentity orientation, premultiplied alpha, extra channels other than one alpha channel, and high-depth samples are rejected. Compressed and decoded allocations are capped at 512 MiB. Decode is synchronous. Arbitrary profile equivalence and live engine rendering have not been established. A rejected JXL falls back to the PNG decoder, which cannot recover its original image automatically. Preserve originals.
