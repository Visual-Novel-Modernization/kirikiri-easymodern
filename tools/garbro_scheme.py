#!/usr/bin/env python3
"""Export an existing GARbro Cx scheme without executing serialized .NET objects.

Requires the optional bounded NRBF parser: python -m pip install nrbf==0.1.2.
GARbro Cx implementation: morkt, MIT; see LICENSES/GARbro.txt.
No game-specific control block is distributed by this project.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zlib

MAX_DATABASE = 32 * 1024 * 1024
SOURCE = Path('ArcFormats/KiriKiri/KiriKiriCx.cs')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def export_scheme(source_root, database, title):
    try:
        import nrbf
    except ImportError as exc:
        raise RuntimeError('Install the optional parser with: python -m pip install nrbf==0.1.2') from exc
    root = Path(source_root).resolve()
    database = Path(database).resolve()
    raw = database.read_bytes()
    if len(raw) > MAX_DATABASE or raw[:8] != b'GARbroDB' or len(raw) < 13:
        raise ValueError('Invalid or oversized GARbro scheme database')
    inflater = zlib.decompressobj()
    payload = inflater.decompress(raw[12:], MAX_DATABASE + 1)
    if len(payload) > MAX_DATABASE or not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
        raise ValueError('Invalid or oversized GARbro database compression stream')
    parsed = nrbf.loads(payload)
    scheme = parsed['SchemeMap']['XP3']['KnownSchemes'][title]
    if scheme.get('__class__') != 'GameRes.Formats.KiriKiri.CxEncryption':
        raise ValueError('Only the original CxEncryption implementation is supported')
    if scheme.get('TpmFileName') is not None or len(scheme.get('ControlBlock', [])) != 1024:
        raise ValueError('Scheme must contain its complete embedded control block')
    if scheme.get('ICrypt+<StartupTjsNotEncrypted>k__BackingField') or scheme.get('ICrypt+<ObfuscatedIndex>k__BackingField'):
        raise ValueError('Startup exclusions and obfuscated indices are unsupported')
    for field, size in [('PrologOrder', 3), ('OddBranchOrder', 6), ('EvenBranchOrder', 8)]:
        values = scheme[field]
        if sorted(values) != list(range(size)):
            raise ValueError(f'Invalid {field}')
    for field in ('m_mask', 'm_offset'):
        if type(scheme[field]) is not int or not 0 <= scheme[field] <= 0xffffffff:
            raise ValueError(f'Invalid {field}')
    if any(type(v) is not int or not 0 <= v <= 0xffffffff for v in scheme['ControlBlock']):
        raise ValueError('Invalid control block word')
    source = (root / SOURCE).read_bytes()
    revision = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'],
                              check=True, text=True, stdout=subprocess.PIPE).stdout.strip()
    return {'schema': 1, 'title': title, 'scheme': scheme, 'provenance': {
        'upstream': 'https://github.com/morkt/GARbro', 'revision': revision,
        'source_path': SOURCE.as_posix(), 'source_sha256': sha256(source),
        'database_sha256': sha256(raw), 'database_version': parsed.get('Version'),
        'parser': 'nrbf 0.1.2', 'license': 'MIT, morkt (LICENSES/GARbro.txt)'}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--database', required=True, type=Path)
    parser.add_argument('--title', default='Island Diary')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    if output == repository or repository in output.parents:
        raise ValueError('Scheme exports must remain outside the repository')
    result = export_scheme(args.source_root, args.database, args.title)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2, ensure_ascii=True)
        output.write('\n')
    print(f'Exported existing GARbro scheme: {args.title}')


if __name__ == '__main__':
    main()
