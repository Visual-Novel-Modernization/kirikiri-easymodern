param(
  [Parameter(Mandatory = $true)][string]$ToolchainRoot,
  [string]$OutDir = (Join-Path $PSScriptRoot 'bin')
)
$ErrorActionPreference = 'Stop'
$gxx = Join-Path $ToolchainRoot 'bin/g++.exe'
$inc = Join-Path $ToolchainRoot 'include'
$lib = Join-Path $ToolchainRoot 'lib'
foreach ($required in @($gxx, (Join-Path $inc 'jxl/decode.h'), (Join-Path $lib 'libjxl.a'), (Join-Path $ToolchainRoot 'bin/libwinpthread-1.dll'))) {
  if (-not (Test-Path -LiteralPath $required)) { throw "Missing prerequisite: $required" }
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
# Static image libraries; matching winpthread runtime is shipped separately.
$common = @('-m32', '-O2', '-std=gnu++17', '-DJXL_STATIC_DEFINE', '-I', $inc, '-L', $lib,
  "-ffile-prefix-map=$PSScriptRoot=.", "-ffile-prefix-map=$ToolchainRoot=toolchain",
  '-Wl,-Bstatic', '-ljxl', '-ljxl_cms', '-lbrotlidec', '-lbrotlicommon', '-lhwy', '-lwinpthread', '-lstdc++', '-lgcc',
  '-Wl,-Bdynamic', '-lcrypt32', '-ladvapi32', '-luser32', '-lkernel32')
& $gxx '-shared' '-s' '-static-libgcc' '-static-libstdc++' '-Wl,--kill-at' (Join-Path $PSScriptRoot 'hook.cpp') '-o' (Join-Path $OutDir 'jxl_hook.dll') @common
if ($LASTEXITCODE -ne 0) { throw 'Hook DLL build failed' }
& $gxx '-municode' '-s' '-static-libgcc' '-static-libstdc++' (Join-Path $PSScriptRoot 'hook_selftest.cpp') '-o' (Join-Path $OutDir 'hook_selftest.exe') @common
if ($LASTEXITCODE -ne 0) { throw 'Selftest build failed' }
Copy-Item -LiteralPath (Join-Path $ToolchainRoot 'bin/libwinpthread-1.dll') -Destination (Join-Path $OutDir 'libwinpthread-1.dll') -Force
Get-Item (Join-Path $OutDir 'jxl_hook.dll'), (Join-Path $OutDir 'hook_selftest.exe'), (Join-Path $OutDir 'libwinpthread-1.dll') | Select-Object Name, Length
