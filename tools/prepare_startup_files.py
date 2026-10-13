#!/usr/bin/env python3
"""Stage physical startup files for an explicit engine -startup argument."""
import argparse
import hashlib
import json
from pathlib import Path

EXPECTED = '25fbd9f90fa7e7a783b1c4485b86e0004257dc056475623ef79bd11a304d0cf5'
WRAPPER = ('// Load the exact-build image hook and disable the archive cipher.\r\n'
           'Plugins.link(System.exePath + "island_jxl_hook.dll");\r\n'
           'Scripts.execStorage(System.exePath + "island_jxl_original_startup.tjs");\r\n')

def prepare(startup, output):
    startup, output = Path(startup), Path(output)
    for path in (startup, output):
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('Symlink input or output is unsupported')
    startup, output = startup.resolve(), output.resolve()
    repository = Path(__file__).resolve().parent.parent
    if output == repository or repository in output.parents or startup.parent in output.parents or output == startup.parent:
        raise ValueError('Outputs must be external and separate from recovered sources')
    original = startup.read_bytes()
    if original[:8] != b'TJS2100\0' or hashlib.sha256(original).hexdigest() != EXPECTED:
        raise ValueError('Exact supported compiled startup is required')
    files = {'island_jxl_startup.tjs': b'\xff\xfe' + WRAPPER.encode('utf-16le'),
             'island_jxl_original_startup.tjs': original}
    report = output / 'startup-files-verification.json'
    if report.exists() or any((output / name).exists() for name in files):
        raise ValueError('Refusing to overwrite staged startup files or evidence')
    output.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (output / name).write_bytes(data)
        if (output / name).read_bytes() != data:
            raise ValueError('Staged startup differs')
    evidence = {'schema': 1, 'source_sha256': EXPECTED,
                'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
                'loading': 'Explicit physical -startup storage; no archive precedence dependency',
                'live_engine_verified': False}
    report.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print('Prepared physical startup files; launch remains user-controlled.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--startup', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.startup, args.output)
