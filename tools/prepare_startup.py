#!/usr/bin/env python3
"""Prepare an external startup XP3 sidecar without installing or launching it.

WARNING: This plain XP3 package is NOT deployable while the game's Cx archive
filter is registered. The archive reader applies that filter independently of
entry protection flags, before the wrapper can load and initialize the hook.

The original startup bytecode is stored unchanged under a unique name. The
UTF-16 wrapper loads the hook synchronously before executing that bytecode.
This command produces staging evidence only. Archive precedence alone does not
resolve the pre-hook filter requirement. An independently verified bootstrap
storage path or an existing compatible encrypted packager is required.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import tempfile
import pipeline
import xp3

ORIGINAL_NAME = 'island_jxl_original_startup.tjs'
WRAPPER = (
    '// Load the validated image hook before original startup initialization.\r\n'
    'Plugins.link("island_jxl_hook.dll");\r\n'
    'Scripts.execStorage("island_jxl_original_startup.tjs");\r\n'
)


def prepare(startup, output, expected_sha256):
    startup, output = Path(startup).resolve(), Path(output).resolve()
    if startup.name.casefold() != 'startup.tjs':
        raise ValueError('Input must be the audited original startup.tjs')
    if any(p.is_symlink() for p in (Path(startup), *Path(startup).parents)):
        raise ValueError('Startup input has a symlink ancestor')
    if output.suffix.lower() != '.xp3':
        raise ValueError('Output must have an .xp3 extension')
    pipeline.external(output, [startup.parent])
    if output.exists() or output.with_name(output.name + '.tmp').exists():
        raise ValueError('Refusing to overwrite an existing archive or temporary output')
    if len(expected_sha256) != 64 or any(c not in '0123456789abcdefABCDEF' for c in expected_sha256):
        raise ValueError('Expected startup SHA-256 must be a 64-digit hexadecimal hash')
    actual_hash = xp3.digest(startup)
    if actual_hash != expected_sha256.lower():
        raise ValueError('Startup bytecode differs from the audited SHA-256')
    with startup.open('rb') as stream:
        if stream.read(8) != b'TJS2100\x00':
            raise ValueError('Input is not the expected TJS2 compiled startup format')
    output.parent.mkdir(parents=True, exist_ok=True)
    report_path = output.with_suffix('.startup-verification.json')
    if report_path.exists():
        raise ValueError('Refusing to overwrite an existing startup verification report')
    with tempfile.TemporaryDirectory(prefix='startup-package-', dir=output.parent) as temp:
        wrapper = Path(temp) / 'startup.tjs'
        wrapper.write_bytes(b'\xff\xfe' + WRAPPER.encode('utf-16le'))
        entries = []
        for name, source in [('startup.tjs', wrapper), (ORIGINAL_NAME, startup)]:
            entries.append({'path': name, 'payload_path': str(source), 'kind': 'copy',
                            'payload_sha256': xp3.digest(source), 'payload_size': source.stat().st_size})
        report = pipeline.write_archive(output, entries)
    if xp3.digest(startup) != actual_hash:
        raise ValueError('Original startup changed during packaging')
    original = next(e for e in report['entries'] if e['path'] == ORIGINAL_NAME)
    if original['payload_sha256'] != actual_hash:
        raise ValueError('Packaged original startup payload differs')
    report['original_startup_sha256'] = actual_hash
    report['wrapper_encoding'] = 'UTF-16LE with BOM'
    report['hook_storage'] = 'island_jxl_hook.dll'
    report['deployment_status'] = 'NOT DEPLOYABLE: plain XP3 startup is filtered before hook initialization while Cx is registered'
    report['deployable'] = False
    report['bootstrap_requirement'] = 'Independently verified storage path bypassing the archive filter, or compatible encrypted packaging'
    report['archive_precedence_verified'] = False
    xp3.json_write(report_path, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--startup', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--startup-sha256', required=True,
                        help='Expected original bytecode SHA-256 from the validated source audit')
    args = parser.parse_args()
    report = prepare(args.startup, args.output, args.startup_sha256)
    print('Prepared external startup sidecar:', report['archive_path'])
    print('Preserved original startup SHA-256:', report['original_startup_sha256'])
    print('NOT DEPLOYABLE while the Cx archive filter is registered.')
    print('Staging evidence only; verify a compatible bootstrap path before deployment.')


if __name__ == '__main__':
    main()
