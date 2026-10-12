# Akiyume JXL Hook

A Windows **x86** plugin that lets one specific KiriKiri game executable load JPEG XL payloads through its existing PNG image handler. Files retain their original archive paths and `.png` names. Ordinary PNG streams continue through the original decoder.


This is an exact-build binary detour (as for now), not a universal KiriKiri image plugin. No game executable, archive, image, script, save file, or prebuilt binary is distributed here.

## Supported target

| Property | Required value |
| --- | --- |
| Architecture | Windows PE32, i386 |
| Executable SHA-256 | `e7ff31ba26e128b795d1526049d97b57f6a89a86b20eabce89d9aed48b240da9` |
| PNG handler RVA | `0x00123B10` |
| First five handler bytes | `55 8B EC 6A FF` |
| Image mode | Mode 0, 8-bit BGRA output |
| Game title | あきゆめくくる (Akiyume Kukuru) |

The actual handler address is the loaded module base plus the RVA. ASLR is supported. The plugin checks the executable hash, PE32 headers, and instruction bytes before installing the detour. A different executable is rejected even if its name matches.

The original development deployment used libjxl 0.11.1 for the 32-bit decoder and cjxl 0.12.0 for conversion. We later added the ASLR fix so that Windows won't remap the address we are trying to tamper with. All 1,395 selected payloads passed native same-version decoder comparison and source-alpha checks.
## Repository layout

- `hook.cpp`: executable validation, PNG detour, stream access, persistent logging, and plugin exports.
- `jxl_decode.h`: shared JXL detection, decoding, RGBA-to-BGRA conversion, and scanline submission.
- `hook_selftest.cpp`: standalone decoder and callback-contract probe.
- `build.ps1`: parameterized x86 MinGW build.
- `tools/pipeline.py`: optional resumable PNG conversion and plaintext XP3 construction/verification utility.
- `AGENTS.md`: operating instructions for coding agents.

## Build

Use Windows, PowerShell, and an i686 MinGW-w64 toolchain with C++17 support. Its prefix must contain `libjxl`, Brotli decoder/common, Highway, and winpthread libraries. All libraries must be compatible 32-bit builds. An x64 library is not interchangeable with an x86 library. x64 support might be added in the future.

Install dependencies separately using your chosen package manager or source builds. This repository does not download dependencies or pin an entire toolchain. Set the toolchain prefix in your shell, then run:

```powershell
# Set MINGW32_ROOT to your installed i686 toolchain prefix first.
./build.ps1 -ToolchainRoot $env:MINGW32_ROOT
```

You can change the output directory with `-OutDir`. The default output is ignored `bin/`. The script builds `jxl_hook.dll` and `hook_selftest.exe`, and copies the matching `libwinpthread-1.dll`. The image libraries and GCC C++ runtime are linked statically, but the winpthread runtime remains a shipped dependency. Do not substitute a random DLL with the same filename.

## Test the decoder without the game

Supply an image you own. Encode with lossless alpha and the intended quality settings:

```powershell
& "$env:JXL_BIN/cjxl.exe" ./fixture.png ./fixture.jxl -q 90 -e 8 --alpha_distance=0 --num_threads=4
./bin/hook_selftest.exe ./fixture.jxl ./fixture.bgra
```

The probe writes tightly packed, top-to-bottom BGRA bytes and prints the compressed payload SHA-256, dimensions, output byte count, and callback commit count. A successful result includes `callbacks=ok`; the commit count must equal image height. The output file is overwritten if it exists.

For exact decoder validation, decode with a 32-bit `djxl` built from the same libjxl version as the hook, force 8-bit output, convert reference RGBA pixels to BGRA, and compare every byte. Compare decoded alpha separately with original PNG alpha. Different libjxl versions can differ in RGB rounding; the original validation observed up to two LSB between 0.11.1 and 0.12.0. Do not label that cross-version comparison byte-exact. Hidden RGB under fully transparent pixels can change; report alpha-weighted visible error separately from whole-RGB error.

The standalone test exercises the shared decoder and synthetic size/scanline callbacks. It does not exercise executable validation, the live detour, engine stream ABI, startup scripts, archive selection, or rendering.

## Optional conversion pipeline

Install Python 3.10 or later and dependencies:

```powershell
python -m pip install -r requirements.txt
python ./tools/pipeline.py --help
```

Provide `cjxl.exe` and `djxl.exe` through `--bin`, the `JXL_BIN` environment variable, or discovery of `cjxl` on PATH. Both programs must be in the same directory. Use external, private working directories for real game data. Generated manifests contain resolved paths and must not be committed or published without sanitization.

The directory layout expected beneath a chosen working root is:

```text
unpacked/
  bgimage/       # extracted background archive entries
  data/          # extracted data archive entries
  fgimage/       # extracted character archive entries
work/            # generated caches and manifest
output/          # generated plaintext XP3 archives
```

The repository does not include an archive extractor. Extract only resources you are authorized to process and independently verify their hashes against the source archive.

Example using a private working root selected in your shell:

```powershell
python ./tools/pipeline.py scan --root $env:JXL_WORK_ROOT --bin $env:JXL_BIN --report ./scan.local.json
python ./tools/pipeline.py selftest --bin $env:JXL_BIN
python ./tools/pipeline.py run --root $env:JXL_WORK_ROOT --bin $env:JXL_BIN --archives bgimage data fgimage --workers 3 --threads 4 -q 90 -e 8
python ./tools/pipeline.py verify "$env:JXL_WORK_ROOT/output/bgimage.xp3" --root $env:JXL_WORK_ROOT --bin $env:JXL_BIN
```

`run` performs conversion followed by building. `convert` only prepares payloads; `build` writes archives from a complete manifest. `verify` checks XP3 structure, segment bounds, unique paths, Adler checksums, and, when a corresponding manifest exists, complete expected payloads and archive SHA-256. The isolated `selftest` tests resume, cache corruption, source preservation, stored/zlib segments, and archive boundaries; its temporary fixtures are removed automatically.

Defaults are quality 90, effort 8, alpha distance 0, three workers, and four threads per encoder/decoder. Don't forget to tune the settings for your CPU. Run one process per work directory and keep script/tool versions unchanged during a batch. 
Resuming a batch is possible. Source/configuration/tool/script hashes and cached payload/candidate/decoded hashes determine reuse. 

Conversion is deliberately conservative: only supported RGB/RGBA PNG input; `data` conversion is restricted to `evimage`; rules, masks, labels, UI, unusual ICC noise, palette/grayscale/high-depth/animated inputs and TLG are preserved. A candidate is selected only if smaller than both the source payload and its known original stored cost. Optional private `*_source.json` audit files provide original segment costs and source hash information. Without those files, original stored-cost evidence is unavailable. Do not infer semantic safety merely because a candidate is smaller. The manifest records selection, reasons, hashes, dimensions, exact alpha checks, and RGB error metrics.

## Install and load manually

1. Confirm the target executable hash with `Get-FileHash -Algorithm SHA256` and compare it with the table above.
2. Close the game yourself before replacing any files. Back up original archives and startup resources outside the game directory, and record their hashes.
3. Copy `jxl_hook.dll` and its matching `libwinpthread-1.dll` beside the executable.
4. Arrange for the engine to execute the following TJS statement before the first affected image is loaded:

```javascript
Plugins.link(System.exePath + "jxl_hook.dll");
```

5. Continue the original startup script unchanged. If using a startup wrapper, preserve the original under a noncolliding storage name and call `Scripts.execStorage` on that name after linking the plugin. Preserve original bytes, including compiled-script bytes. The original script is not provided here.
6. Install only independently verified candidate archives. Preserve original storage paths and `.png` names so the existing PNG dispatch reaches this handler. Preserve archive load order and patch priority. Do not replace an unchanged archive with a larger rebuilt copy.
7. Start the game manually. Check the title, ordinary backgrounds, CG, alpha edges, transitions, and save/load paths. Keep backups and conversion caches until the user confirms normal operation.

Copying the DLL alone does not load it. A startup script in the wrong archive, a later patch overriding startup, signature enforcement, or a failure to execute `Plugins.link` can prevent installation. The conversion utility does not inject startup or install anything. Deployment is intentionally explicit; no script in this repository starts or terminates the game.

## Runtime logs and troubleshooting

The hook appends `jxl_hook.log` beside the executable and also sends messages to `OutputDebugString`. Runtime logs contain addresses, dimensions, and payload hashes; keep them private and untracked.

- `installed PNG detour at ...`: the exact-target checks and patch installation succeeded.
- `JXL payloadSHA256=... dimensions=...`: decoding and scanline submission completed. Match the hash to the conversion manifest to identify the resource.
- `refusing install: executable SHA256 ...`: the executable differs. Do not disable the check; reverse-engineer and validate that build separately.
- `refusing install: PNG entry bytes changed`: the expected code is absent or modified. Investigate other hooks and executable changes.
- `rejecting JXL with unsupported PNG mode=...`: that resource uses an unsupported loading mode. Restore its original PNG and rebuild the archive.
- No log: check startup execution, plugin/dependency locations, plugin load errors, and directory write permissions.

An earlier implementation incorrectly required the preferred PE image base and rejected valid ASLR loads. The current code uses the actual module base plus RVA. Do not reintroduce fixed absolute addresses or turn off ASLR as a workaround.

## Engine contract and limits

The exact handler is `__cdecl`, with format data, callback data, size/scanline/meta callbacks, a binary stream pointer, key index, and mode arguments. The stream is not COM: vtable slot 0 is a `__cdecl` seek function returning a 64-bit position; slot 1 is a `__cdecl` read function. The hook never releases or deletes the stream. It peeks at JXL magic and restores position before PNG fallback. Only JXL streams are read in full.

The hook calls the size callback once, obtains `scanline(y)`, copies one BGRA row, and calls `scanline(-1)` after every row. Those commit calls are required by the engine. Installation copies five known complete instructions/bytes into a trampoline and patches a relative jump. Install at startup before image-loader threads can execute this handler; installation is not a general thread-suspending patch framework.

Only mode 0 is supported. Palette mode 1 and grayscale/key mode 2 are not reproduced; mode-0 key-index transformations and metadata callbacks are not emulated. Animated JXL, nonidentity orientation, multiple extra channels, and non-alpha extra channels are rejected. Output is 8-bit BGRA. Full compressed input is limited to 512 MiB; decoded images are fully allocated and decoded synchronously without a practical pixel budget or a parallel runner. Color/profile equivalence with the original PNG handler is not established for arbitrary profiles.

Unsupported or failed JXL goes to the original PNG handler, which generally cannot decode it. This exposes an image-load error; it does not recover an original image automatically. Keep unsupported resources in their original format.

Once installed, `V2Unlink` refuses dynamic unloading to avoid freeing a trampoline while another thread enters it. Normal process exit releases memory.

