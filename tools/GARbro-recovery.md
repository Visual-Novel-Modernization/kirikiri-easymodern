# Exact source recovery using existing GARbro CxEncryption

The game is supported by the official **Island Diary** scheme in GARbro's XP3 database. Use the original Cx implementation and database parameters; constant XOR recovery does not preserve all resources. No game-specific encryption key or control block is included in this repository.

The tools were verified against upstream GARbro revision `c23bd588ddfe7907150df215f8725fe25d5b41df`, `ArcFormats/KiriKiri/KiriKiriCx.cs` and `ArcFormats/Resources/Formats.dat`. Upstream source: https://github.com/morkt/GARbro. Source copyright 2014-2016 morkt, MIT; see `../LICENSES/GARbro.txt`. The exporter records the actual revision, source SHA-256 and database SHA-256 for the supplied checkout. Recovery requires the source hash to match that export.

Requires Python 3.10+, Git, optional bounded NRBF parser `nrbf==0.1.2`, and PowerShell 7.3+ with .NET `ZLibStream`. The NRBF parser reads data without instantiating or executing serialized .NET objects. Install it in a suitable external environment:

```powershell
python -m pip install nrbf==0.1.2
```

Keep the source checkout, original archives, exported scheme, indices and all recovered outputs outside this repository. Choose these external locations explicitly:

```powershell
python tools/garbro_scheme.py --source-root $env:GARBRO_SOURCE --database $env:GARBRO_DATABASE --title 'Island Diary' --output $env:GARBRO_SCHEME
python tools/xp3.py inspect --archive "$env:JXL_ORIGINAL/data.xp3" --report "$env:JXL_WORK/data-index.json"
./tools/recover_garbro.ps1 -SourceRoot $env:GARBRO_SOURCE -Scheme $env:GARBRO_SCHEME -Index "$env:JXL_WORK/data-index.json" -Archive "$env:JXL_ORIGINAL/data.xp3" -Destination "$env:JXL_RECOVERED/data"
python tools/xp3.py audit --archive "$env:JXL_ORIGINAL/data.xp3" --extracted "$env:JXL_RECOVERED/data" --extractor tools/recover_garbro.ps1 --report "$env:JXL_WORK/data-source.json"
```

Repeat the index, recovery and audit commands for `adult.xp3` and its own destination. Recovery refuses an existing destination, validates the archive hash against its index, checks safe entry paths, reads every stored segment fully, limits allocations, checks exact decompressed and aggregate sizes, and verifies original Adler32 before writing each file. Failure may leave previously verified entries in the newly created destination; keep that partial directory as diagnostic evidence and select a fresh destination for a retry.

The recovered payload is the exact post-filter archive content. Unlike GARbro's normal extraction postprocessing, this tool does not normalize encoded text scripts or alter their sizes. A compiled `startup.tjs` remains compiled TJS bytecode. The full original strict XP3 audit remains mandatory before conversion; it independently verifies inventory, original segment evidence and recovered Adler32/SHA-256.

`recover_garbro.ps1` compiles the supplied original source's key generator, bytecode interpreter and decryption filter. It removes only `Init()` (external TPM loading) and supplies minimal standalone adapter types, because the supported database object embeds all 1024 control-block words. It rejects external TPM schemes, startup exclusions, index obfuscation and other crypt classes. It never invokes the game. Each output tree has a sibling `.recovery.json` with source/database provenance, input hashes, entry checksums and recovered SHA-256 values.

The three verification samples matched `BG000_00.png` Adler32 `ce097986`, `EV07_03.png` `fed27133`, and compiled `startup.tjs` `e425cd85`. This establishes exact decryption for those samples; whole-archive source audits provide the inventory-wide acceptance check.
