# Execute GARbro's existing Cx source with an externally exported official scheme.
# Upstream: https://github.com/morkt/GARbro (MIT, morkt; LICENSES/GARbro.txt).
# No game process is invoked. Requires PowerShell 7.3+ (.NET ZLibStream).
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceRoot,
    [Parameter(Mandatory)][string]$Scheme,
    [Parameter(Mandatory)][string]$Index,
    [Parameter(Mandatory)][string]$Archive,
    [Parameter(Mandatory)][string]$Destination
)
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$destinationPath = [IO.Path]::GetFullPath($Destination)
if ($destinationPath.Equals($repository, [StringComparison]::OrdinalIgnoreCase) -or
    $destinationPath.StartsWith($repository + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Recovered assets must remain outside the repository.'
}
if ((Test-Path -LiteralPath $destinationPath) -or (Test-Path -LiteralPath ($destinationPath + '.recovery.json'))) {
    throw 'Destination and its recovery report must not already exist.'
}
$export = Get-Content -LiteralPath $Scheme -Raw -Encoding utf8 | ConvertFrom-Json
if ($export.schema -ne 1 -or $export.scheme.__class__ -ne 'GameRes.Formats.KiriKiri.CxEncryption') {
    throw 'Expected an official CxEncryption scheme export.'
}
$j = $export.scheme
if ($null -ne $j.TpmFileName -or $j.ControlBlock.Count -ne 1024 -or
    $j.'ICrypt+<StartupTjsNotEncrypted>k__BackingField' -or $j.'ICrypt+<ObfuscatedIndex>k__BackingField') {
    throw 'Scheme requires unsupported external state or index handling.'
}
foreach ($field in @('PrologOrder', 'OddBranchOrder', 'EvenBranchOrder')) {
    $length = @{PrologOrder=3; OddBranchOrder=6; EvenBranchOrder=8}[$field]
    if (($j.$field | Sort-Object) -join ',' -ne ((0..($length-1)) -join ',')) { throw "Invalid $field." }
}
$sourcePath = Join-Path $SourceRoot 'ArcFormats/KiriKiri/KiriKiriCx.cs'
$sourceHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($sourceHash -ne $export.provenance.source_sha256) { throw 'GARbro source hash differs from scheme provenance.' }
$idx = Get-Content -LiteralPath $Index -Raw -Encoding utf8 | ConvertFrom-Json
$archivePath = [IO.Path]::GetFullPath($Archive)
$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($idx.schema -ne 1 -or $archiveHash -ne $idx.archive_sha256 -or
    (Get-Item -LiteralPath $archivePath).Length -ne $idx.archive_size) {
    throw 'Archive does not match the strict XP3 index.'
}
$src = Get-Content -LiteralPath $sourcePath -Raw -Encoding utf8
# The official scheme embeds its control block. Remove only the external TPM
# loader; preserve GARbro's key generator, bytecode interpreter and filter.
$start = $src.IndexOf('        public override void Init (ArcFile arc)')
$end = $src.IndexOf('        uint GetBaseOffset', $start)
if ($start -lt 0 -or $end -le $start) { throw 'Unsupported GARbro source layout.' }
$src = $src.Remove($start, $end - $start)
$adapter = @'
namespace GameRes.Formats.KiriKiri {
 public class Xp3Entry { public uint Hash; }
 public abstract class ICrypt {
  public virtual byte Decrypt(Xp3Entry e,long o,byte v){return v;}
  public abstract void Decrypt(Xp3Entry e,long o,byte[] b,int p,int n);
  public virtual void Encrypt(Xp3Entry e,long o,byte[] b,int p,int n){}
 }
 public class Recovery : CxEncryption {
  public Recovery(CxScheme s):base(s){}
  public static byte[] ReadSegment(System.IO.Stream archive,long offset,int stored,int size,bool compressed) {
   if (offset<19 || stored<0 || size<0 || offset>archive.Length-stored)
    throw new System.IO.InvalidDataException("Segment outside archive");
   archive.Position=offset;
   byte[] raw=new byte[stored];
   int read=0;
   while(read<stored) {int n=archive.Read(raw,read,stored-read);if(n==0)throw new System.IO.EndOfStreamException();read+=n;}
   if(!compressed) {if(stored!=size)throw new System.IO.InvalidDataException("Raw size mismatch");return raw;}
   using(var input=new System.IO.MemoryStream(raw,false))
   using(var z=new System.IO.Compression.ZLibStream(input,System.IO.Compression.CompressionMode.Decompress)) {
    byte[] output=new byte[size];read=0;
    while(read<size) {int n=z.Read(output,read,size-read);if(n==0)throw new System.IO.EndOfStreamException("Short inflated segment");read+=n;}
    if(z.ReadByte()!=-1)throw new System.IO.InvalidDataException("Inflated segment exceeds declared size");
    if(input.Position!=input.Length)throw new System.IO.InvalidDataException("Trailing compressed segment bytes");
    return output;
   }
  }
  public static uint Adler(byte[] data) {
   uint a=1,b=0;foreach(byte v in data){a=(a+v)%65521;b=(b+a)%65521;}return(b<<16)|a;
  }
  public static string Hash(byte[] data) {return System.Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data)).ToLowerInvariant();}
 }
}
'@
Add-Type -TypeDefinition ($src + $adapter)
$s = [GameRes.Formats.KiriKiri.CxScheme]::new()
$s.Mask = [uint32]$j.m_mask; $s.Offset = [uint32]$j.m_offset
$s.PrologOrder = [byte[]]$j.PrologOrder; $s.OddBranchOrder = [byte[]]$j.OddBranchOrder
$s.EvenBranchOrder = [byte[]]$j.EvenBranchOrder; $s.ControlBlock = [uint32[]]$j.ControlBlock
$filter = [GameRes.Formats.KiriKiri.Recovery]::new($s)
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
# Validate all entry paths before creating any output.
foreach ($entry in $idx.entries) {
    $name = [string]$entry.path
    if ([string]::IsNullOrEmpty($name) -or $name.Contains('\') -or $name.Contains(':') -or
        $name.Contains([char]0) -or $name.StartsWith('/') -or -not $seen.Add($name)) { throw "Unsafe or duplicate entry: $name" }
    foreach ($part in $name.Split('/')) {
        if ([string]::IsNullOrEmpty($part) -or $part -in @('.', '..') -or $part.EndsWith(' ') -or
            $part.EndsWith('.') -or $part -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') { throw "Unsafe entry: $name" }
    }
    if ($entry.protection -notin @(0, 2147483648) -or $entry.payload_size -lt 0 -or
        $entry.payload_size -gt 536870912 -or $entry.stored_size -lt 0 -or -not $entry.segments.Count) {
        throw "Unsupported entry metadata: $name"
    }
}
[IO.Directory]::CreateDirectory($destinationPath) | Out-Null
$results = [Collections.Generic.List[object]]::new()
$arc = [IO.File]::OpenRead($archivePath)
try {
    foreach ($e in $idx.entries) {
        $all = [IO.MemoryStream]::new([int]$e.payload_size)
        try {
            $storedTotal = [long]0
            foreach ($sg in $e.segments) {
                if ($sg.flags -notin @(0, 1) -or $sg.stored_size -lt 0 -or $sg.stored_size -gt 536870912 -or
                    $sg.size -lt 0 -or $sg.size -gt 536870912 -or $all.Length + $sg.size -gt $e.payload_size) {
                    throw "Invalid segment metadata: $($e.path)"
                }
                $buf = [GameRes.Formats.KiriKiri.Recovery]::ReadSegment($arc, [long]$sg.offset,
                    [int]$sg.stored_size, [int]$sg.size, ($sg.flags -eq 1))
                $all.Write($buf, 0, $buf.Length)
                $storedTotal += [long]$sg.stored_size
            }
            if ($all.Length -ne $e.payload_size -or $storedTotal -ne $e.stored_size) { throw "Aggregate size mismatch: $($e.path)" }
            $b = $all.ToArray()
        } finally { $all.Dispose() }
        $cryptEntry = [GameRes.Formats.KiriKiri.Xp3Entry]::new()
        $cryptEntry.Hash = [uint32]$e.adler32
        if ($e.protection -eq 2147483648) { $filter.Decrypt($cryptEntry, 0, $b, 0, $b.Length) }
        $checksum = [GameRes.Formats.KiriKiri.Recovery]::Adler($b)
        if ($checksum -ne $cryptEntry.Hash) { throw "Recovered Adler32 mismatch: $($e.path)" }
        $out = Join-Path $destinationPath $e.path
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($out)) | Out-Null
        $output = [IO.File]::Open($out, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $output.Write($b, 0, $b.Length) } finally { $output.Dispose() }
        $results.Add([ordered]@{path=$e.path; size=$b.Length; adler32=('{0:x8}' -f $checksum);
            sha256=[GameRes.Formats.KiriKiri.Recovery]::Hash($b)})
    }
} finally { $arc.Dispose() }
$report = [ordered]@{schema=1; archive_sha256=$archiveHash;
    index_sha256=(Get-FileHash -LiteralPath $Index -Algorithm SHA256).Hash.ToLowerInvariant();
    scheme_sha256=(Get-FileHash -LiteralPath $Scheme -Algorithm SHA256).Hash.ToLowerInvariant();
    provenance=$export.provenance; title=$export.title; entry_count=$results.Count; entries=$results}
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath ($destinationPath + '.recovery.json') -Encoding utf8
Write-Output "Recovered and checksum-verified $($results.Count) entries. Run tools/xp3.py audit before conversion."
