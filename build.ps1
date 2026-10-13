param(
  [Parameter(Mandatory = $true)][string]$ToolchainRoot,
  [Parameter(Mandatory = $true)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
$resolvedOut = [IO.Path]::GetFullPath($OutDir)
$repo = [IO.Path]::GetFullPath($PSScriptRoot)
if ($resolvedOut -eq $repo -or $resolvedOut.StartsWith($repo + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'Build outputs must be outside the source repository.'
}
$gxx = Join-Path $ToolchainRoot 'bin/g++.exe'
$inc = Join-Path $ToolchainRoot 'include'
$lib = Join-Path $ToolchainRoot 'lib'
foreach ($required in @($gxx, (Join-Path $inc 'jxl/decode.h'), (Join-Path $lib 'libjxl.a'), (Join-Path $ToolchainRoot 'bin/libwinpthread-1.dll'))) {
  if (-not (Test-Path -LiteralPath $required)) { throw "Missing prerequisite: $required" }
}
$machine = & $gxx '-dumpmachine'
if ($LASTEXITCODE -ne 0 -or $machine -notmatch '^i686-') { throw 'An i686 MinGW toolchain is required.' }
New-Item -ItemType Directory -Force -Path $resolvedOut | Out-Null
$common = @('-m32', '-O2', '-std=gnu++17', '-DJXL_STATIC_DEFINE', '-I', $inc, '-L', $lib,
  "-ffile-prefix-map=$PSScriptRoot=.", "-ffile-prefix-map=$ToolchainRoot=toolchain",
  '-Wl,-Bstatic', '-ljxl', '-ljxl_cms', '-lbrotlidec', '-lbrotlicommon', '-lhwy', '-lwinpthread', '-lstdc++', '-lgcc',
  '-Wl,-Bdynamic', '-lcrypt32', '-ladvapi32', '-luser32', '-lkernel32', '-Wl,--dynamicbase', '-Wl,--nxcompat', '-Wl,--no-insert-timestamp', '-Wl,--exclude-all-symbols', '-Wl,--exclude-libs,ALL')
& $gxx '-shared' '-s' '-static-libgcc' '-static-libstdc++' '-Wl,--kill-at' (Join-Path $PSScriptRoot 'hook.cpp') (Join-Path $PSScriptRoot 'hook.def') '-o' (Join-Path $resolvedOut 'island_jxl_hook.dll') @common
if ($LASTEXITCODE -ne 0) { throw 'Hook DLL build failed' }
& $gxx '-municode' '-s' '-static-libgcc' '-static-libstdc++' (Join-Path $PSScriptRoot 'hook_selftest.cpp') '-o' (Join-Path $resolvedOut 'hook_selftest.exe') @common
if ($LASTEXITCODE -ne 0) { throw 'Selftest build failed' }
Copy-Item -LiteralPath (Join-Path $ToolchainRoot 'bin/libwinpthread-1.dll') -Destination (Join-Path $resolvedOut 'libwinpthread-1.dll') -Force
Get-FileHash -LiteralPath (Join-Path $resolvedOut 'island_jxl_hook.dll'), (Join-Path $resolvedOut 'hook_selftest.exe'), (Join-Path $resolvedOut 'libwinpthread-1.dll') -Algorithm SHA256
