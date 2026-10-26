param(
  [string]$ToolchainRoot = $env:MINGW32_ROOT,
  [string]$OutDir = (Join-Path $PSScriptRoot 'bin')
)
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ToolchainRoot)) {
  throw 'Specify -ToolchainRoot or set the MINGW32_ROOT environment variable to your 32-bit MSYS2 mingw32 prefix.'
}

$gxx = Join-Path $ToolchainRoot 'bin/g++.exe'
$inc = Join-Path $ToolchainRoot 'include'
$lib = Join-Path $ToolchainRoot 'lib'
$winpthread = Join-Path $ToolchainRoot 'bin/libwinpthread-1.dll'

foreach ($required in @(
  $gxx,
  (Join-Path $inc 'jxl/decode.h'),
  (Join-Path $lib 'libjxl.a'),
  (Join-Path $inc 'dav1d/dav1d.h'),
  (Join-Path $lib 'libdav1d.a'),
  $winpthread
)) {
  if (-not (Test-Path -LiteralPath $required)) { throw "Missing prerequisite: $required" }
}

$machine = & $gxx '-dumpmachine'
if ($LASTEXITCODE -ne 0 -or $machine -notmatch '^i686-') {
  throw 'An i686 (32-bit) MinGW-w64 toolchain is required.'
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$srcDir = Join-Path $PSScriptRoot 'src'

# Common static linking flags for 32-bit KiriKiri JXL plugin
$jxlCommon = @(
  '-m32', '-O2', '-std=gnu++17', '-DJXL_STATIC_DEFINE',
  '-I', $inc, '-I', $srcDir, '-L', $lib,
  "-ffile-prefix-map=$PSScriptRoot=.", "-ffile-prefix-map=$ToolchainRoot=toolchain",
  '-Wl,-Bstatic', '-ljxl', '-ljxl_cms', '-lbrotlidec', '-lbrotlicommon', '-lhwy', '-lwinpthread', '-lstdc++', '-lgcc',
  '-Wl,-Bdynamic', '-lcrypt32', '-ladvapi32', '-luser32', '-lkernel32'
)

# Static linking flags for 32-bit KiriKiri AV1 (libdav1d) plugin
$av1Common = @(
  '-m32', '-O2', '-std=gnu++17',
  '-I', $inc, '-I', $srcDir, '-L', $lib,
  "-ffile-prefix-map=$PSScriptRoot=.", "-ffile-prefix-map=$ToolchainRoot=toolchain",
  '-Wl,-Bstatic', '-ldav1d', '-lwinpthread', '-lstdc++', '-lgcc',
  '-Wl,-Bdynamic', '-lmsacm32', '-lwinmm', '-lole32', '-luser32', '-lkernel32'
)

# Combined flags for hook_selftest.exe
$selftestCommon = @(
  '-m32', '-O2', '-std=gnu++17', '-DJXL_STATIC_DEFINE',
  '-I', $inc, '-I', $srcDir, '-L', $lib,
  "-ffile-prefix-map=$PSScriptRoot=.", "-ffile-prefix-map=$ToolchainRoot=toolchain",
  '-Wl,-Bstatic', '-ljxl', '-ljxl_cms', '-lbrotlidec', '-lbrotlicommon', '-lhwy', '-ldav1d', '-lwinpthread', '-lstdc++', '-lgcc',
  '-Wl,-Bdynamic', '-lmsacm32', '-lwinmm', '-lcrypt32', '-ladvapi32', '-luser32', '-lkernel32'
)

Write-Host "Building 32-bit jxl_hook.dll..."
& $gxx '-shared' '-s' '-static-libgcc' '-static-libstdc++' '-Wl,--kill-at' (Join-Path $srcDir 'hook.cpp') (Join-Path $srcDir 'hook.def') '-o' (Join-Path $OutDir 'jxl_hook.dll') @jxlCommon
if ($LASTEXITCODE -ne 0) { throw 'JXL Hook DLL build failed' }

Write-Host "Building 32-bit av1_gst_hook.dll (statically linked libdav1d)..."
& $gxx '-shared' '-s' '-static-libgcc' '-static-libstdc++' '-Wl,--kill-at' (Join-Path $srcDir 'video_dav1d.cpp') (Join-Path $srcDir 'video_dav1d.def') '-o' (Join-Path $OutDir 'av1_gst_hook.dll') @av1Common
if ($LASTEXITCODE -ne 0) { throw 'AV1 Hook DLL build failed' }

Write-Host "Building 32-bit hook_selftest.exe..."
& $gxx '-municode' '-s' '-static-libgcc' '-static-libstdc++' (Join-Path $srcDir 'hook_selftest.cpp') '-o' (Join-Path $OutDir 'hook_selftest.exe') @selftestCommon
if ($LASTEXITCODE -ne 0) { throw 'Selftest executable build failed' }

Copy-Item -LiteralPath $winpthread -Destination (Join-Path $OutDir 'libwinpthread-1.dll') -Force

Write-Host "=== Build Deliverables ==="
Get-Item (Join-Path $OutDir 'jxl_hook.dll'), (Join-Path $OutDir 'av1_gst_hook.dll'), (Join-Path $OutDir 'hook_selftest.exe'), (Join-Path $OutDir 'libwinpthread-1.dll') | Select-Object Name, Length
