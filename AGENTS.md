# Agent instructions

- Keep source, comments, documentation, and commit messages in English.
- Never commit machine-specific paths, usernames, local configuration, game assets, logs, generated reports, binary build products, credentials, or extracted scripts.
- Accept tool locations and working directories as explicit inputs or environment variables. Keep examples relative or use environment variables.
- Read README.md before changing the detour. This implementation supports one exact executable and calling convention. Do not remove the executable hash or instruction-byte checks to make another build load.
- Keep address calculations relative to the actual module base. ASLR is supported and must not be disabled.
- Load the plugin during startup before concurrent image decoding. Do not add dynamic detour teardown.
- Preserve original files. Do not launch or stop a user's game, install a plugin, overwrite game archives, or delete backups without task authorization. A request to review or build does not authorize those operations.
- Run isolated synthetic tests first. The selftest checks decoding and callback sequencing; it cannot prove engine ABI, detour installation, rendering, or visual correctness.
- Compare native BGRA against the same version of 32-bit djxl. Record cross-version differences separately; never widen exact-match tolerances to hide a version mismatch. Verify alpha against source pixels.
- Run only one conversion process per work directory. Keep completed caches until runtime confirmation. Do not edit pipeline.py during an active batch because its hash is part of cache validity.
- Recheck Git's staged file list and diff for private information before each commit. Keep generated build/runtime evidence outside tracked files.
