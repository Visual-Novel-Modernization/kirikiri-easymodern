# Agent instructions

- Keep all source, documentation, comments, and commits in English.
- This project supports one independently analyzed ISLAND DIARY executable. Never substitute another game's hash, handler RVA, ABI, or startup assumptions.
- Require the exact executable SHA-256 and complete expected handler prologue before patching. Compute all engine addresses from the actual loaded module base. Preserve ASLR.
- Never launch, terminate, or restart the game. Live rendering tests belong to the user.
- Preserve original game files and archives. Keep extracted assets, output archives, builds, manifests, reports, logs, caches, and backups outside this repository.
- Only generic logic may be reused from other projects. Document engine ABI evidence and distinguish synthetic verification from live engine testing.
- Conversion must use quality 90, effort 8, lossless alpha, at most three workers and four threads per tool. Hold one conversion-process lock. Preserve unsupported formats and semantics-sensitive UI, rule, mask, and thumbnail images.
- Verify source XP3 structure, paths, segments, Adler32, and SHA-256 before conversion. Bind native evidence to each manifest key, source and payload hash, configuration, hook and selftest binary hashes, and matching 32-bit djxl. Reject stale evidence.
- Compare native BGRA byte for byte against the matching decoder and alpha against source pixels. Never use tolerance to hide version differences.
- Parameterize tool and workspace locations. Never commit local paths, usernames, credentials, binary products, runtime JSON, or game assets.
