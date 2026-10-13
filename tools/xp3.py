#!/usr/bin/env python3
"""Strict XP3 index, segment and source audit. No game process is invoked."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib

MAGIC = b'XP3\r\n \n\x1a\x8bg\x01'
LIMIT = 512 * 1024 * 1024
BLOCK = 1024 * 1024


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(BLOCK), b''):
            h.update(b)
    return h.hexdigest()


def json_write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(value, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
    tmp.replace(path)


def safe(name):
    if not name or '\\' in name or ':' in name or '\0' in name or name.startswith('/'):
        raise ValueError(f'Unsafe XP3 name: {name!r}')
    if any(p in ('', '.', '..') or p.endswith((' ', '.')) for p in name.split('/')):
        raise ValueError(f'Unsafe XP3 components: {name!r}')
    reserved = {'con', 'prn', 'aux', 'nul'} | {f'{p}{n}' for p in ('com', 'lpt') for n in range(1, 10)}
    if any(p.split('.')[0].casefold() in reserved for p in name.split('/')):
        raise ValueError(f'Reserved XP3 name: {name!r}')
    return name


def read_exact(f, n):
    b = f.read(n)
    if len(b) != n:
        raise ValueError('Truncated XP3')
    return b


def inflate(b, n):
    z = zlib.decompressobj()
    out = z.decompress(b, n + 1)
    if len(out) != n or not z.eof or z.unused_data or z.unconsumed_tail:
        raise ValueError('Invalid compressed XP3 size or stream')
    return out


def chunks(b):
    p = 0
    while p < len(b):
        if len(b) - p < 12:
            raise ValueError('Truncated XP3 chunk')
        tag, n = struct.unpack_from('<4sQ', b, p)
        p += 12
        if n > len(b) - p:
            raise ValueError('XP3 chunk outside index')
        yield tag, b[p:p+n]
        p += n


def index(path):
    path = Path(path)
    size = path.stat().st_size
    entries, index_ranges, seen, excluded = [], [], set(), []
    with path.open('rb') as f:
        if read_exact(f, 11) != MAGIC:
            raise ValueError('Not a standard XP3 header')
        offset = struct.unpack('<Q', read_exact(f, 8))[0]
        while True:
            if offset in seen or len(seen) >= 1024 or not 19 <= offset < size:
                raise ValueError('Invalid/cyclic index chain')
            seen.add(offset)
            f.seek(offset)
            flags = read_exact(f, 1)[0]
            if flags & ~0x81:
                raise ValueError('Nonstandard XP3 index flags')
            stored = struct.unpack('<Q', read_exact(f, 8))[0]
            raw = struct.unpack('<Q', read_exact(f, 8))[0] if flags & 1 else stored
            if max(stored, raw) > LIMIT or f.tell() + stored + (8 if flags & 128 else 0) > size:
                raise ValueError('XP3 index outside bounds/limit')
            packed = read_exact(f, stored)
            data = inflate(packed, raw) if flags & 1 else packed
            next_offset = struct.unpack('<Q', read_exact(f, 8))[0] if flags & 128 else None
            index_ranges.append((offset, f.tell()))
            for tag, body in chunks(data):
                if tag != b'File':
                    raise ValueError(f'Nonstandard XP3 root chunk: {tag!r}')
                children = {}
                for t, v in chunks(body):
                    if t in children:
                        raise ValueError('Duplicate XP3 file chunk')
                    children[t] = v
                if not {b'info', b'segm', b'adlr'} <= set(children) or set(children) - {b'info', b'segm', b'adlr', b'time'}:
                    raise ValueError('Nonstandard XP3 file metadata')
                if b'time' in children and len(children[b'time']) != 8:
                    raise ValueError('Invalid XP3 timestamp chunk')
                info = children[b'info']
                if len(info) < 22:
                    raise ValueError('Short XP3 info')
                protection, original, archived, units = struct.unpack_from('<IQQH', info)
                # This game includes one terminal UTF-16 NUL beyond name_units.
                encoded = info[22:]
                if len(encoded) == units * 2 + 2 and encoded[-2:] == b'\0\0':
                    encoded = encoded[:-2]
                elif len(encoded) != units * 2:
                    raise ValueError('Invalid XP3 UTF-16 length')
                name = encoded.decode('utf-16le', errors='strict')
                if name.endswith('\0'):
                    name = name[:-1]
                safe(name)
                if protection not in (0, 0x80000000):
                    raise ValueError('Unsupported XP3 protection flags')
                segm, adlr = children[b'segm'], children[b'adlr']
                if not segm or len(segm) % 28 or len(adlr) != 4:
                    raise ValueError('Invalid segment/checksum metadata')
                segments = []
                for p in range(0, len(segm), 28):
                    flag, pos, n, s = struct.unpack_from('<IQQQ', segm, p)
                    if flag not in (0, 1) or pos < 19 or pos + s > size or (flag == 0 and n != s):
                        raise ValueError('Invalid XP3 segment')
                    segments.append({'flags': flag, 'offset': pos, 'size': n, 'stored_size': s})
                if sum(s['size'] for s in segments) != original or sum(s['stored_size'] for s in segments) != archived:
                    if (protection == 0 and original == archived == 910 and len(segments) == 1
                            and segments[0] == {'flags': 0, 'offset': 88, 'size': 157, 'stored_size': 157}
                            and name.startswith('$$$ This is a protected archive. $$$')
                            and struct.unpack('<I', adlr)[0] == 1754764004):
                        # Deliberate invalid warning decoy in both game archives, not an engine entry.
                        excluded.append({'path': name, 'reason': 'Malformed protected-archive warning decoy',
                                         'info_size': original, 'segment_size': 157,
                                         'metadata_sha256': hashlib.sha256(body).hexdigest()})
                        continue
                    raise ValueError(f'XP3 aggregate size mismatch: {name}')
                entries.append({'path': name, 'protection': protection, 'payload_size': original,
                                'stored_size': archived, 'adler32': struct.unpack('<I', adlr)[0], 'segments': segments})
            if next_offset is None:
                break
            offset = next_offset
    names = [e['path'].casefold() for e in entries]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate/case-colliding XP3 paths')
    records = sorted((s['offset'], s['offset'] + s['stored_size'], s['flags'], s['size'], e['adler32'], e['protection'])
                     for e in entries for s in e['segments'] if s['stored_size'])
    for a, b in zip(records, records[1:]):
        if a[1] > b[0] and a != b:
            raise ValueError('Partially overlapping or inconsistent shared XP3 segments')
    ranges = [(r[0], r[1]) for r in records]
    for a, b in ranges:
        if any(a < y and b > x for x, y in index_ranges):
            raise ValueError('XP3 segment overlaps index')
    return {'schema': 1, 'archive_path': str(path.resolve()), 'archive_sha256': digest(path),
            'archive_size': size, 'index_ranges': index_ranges, 'excluded_decoys': excluded, 'entries': entries}


def payload(path, entry, transform=None):
    with Path(path).open('rb') as f:
        logical = 0
        for s in entry['segments']:
            f.seek(s['offset'])
            remaining, count = s['stored_size'], 0
            decoder = zlib.decompressobj() if s['flags'] else None
            while remaining:
                b = read_exact(f, min(BLOCK, remaining))
                remaining -= len(b)
                while True:
                    out = decoder.decompress(b, BLOCK) if decoder else b
                    count += len(out)
                    if count > s['size']:
                        raise ValueError('XP3 decompression exceeds declared size')
                    if transform and entry['protection']:
                        out = transform(out, entry['adler32'], logical)
                    logical += len(out)
                    yield out
                    b = decoder.unconsumed_tail if decoder else b''
                    if not b:
                        break
            if count != s['size'] or (decoder and (not decoder.eof or decoder.unused_data)):
                raise ValueError('Invalid/trailing XP3 segment stream')


def audit(path, extracted=None, transform=None, extract=None):
    report = index(path)
    if extract and any(e['protection'] for e in report['entries']) and not transform:
        raise ValueError('Protected extraction requires a verified existing filter; use recovered --extracted evidence')
    if extracted:
        source_root = Path(extracted)
        if any(p.is_symlink() for p in (source_root, *source_root.parents)):
            raise ValueError('Extracted source has symlink ancestor')
    for e in report['entries']:
        if extracted:
            source_path = Path(extracted) / e['path']
            if any(p.is_symlink() for p in (source_path, *source_path.parents)):
                raise ValueError('Extracted payload has symlink ancestor')
        h, adler = hashlib.sha256(), 1
        stored_hash = hashlib.sha256()
        with Path(path).open('rb') as f:
            for s in e['segments']:
                f.seek(s['offset'])
                remaining = s['stored_size']
                while remaining:
                    b = read_exact(f, min(BLOCK, remaining)); remaining -= len(b); stored_hash.update(b)
        e['stored_sha256'] = stored_hash.hexdigest()
        destination = Path(extract) / e['path'] if extract else None
        if destination:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                raise ValueError('Extraction refuses existing files')
        writer = destination.open('xb') if destination else None
        try:
            raw_hash = hashlib.sha256()
            for b in payload(path, e, transform):
                raw_hash.update(b)
                if not (extracted and e['protection'] and not transform):
                    h.update(b); adler = zlib.adler32(b, adler)
                    if writer:
                        writer.write(b)
            e['segment_payload_sha256'] = raw_hash.hexdigest()
            if extracted and e['protection'] and not transform:
                if extract:
                    raise ValueError('Protected extraction requires a verified filter')
                source = Path(extracted) / e['path']
                if source.is_symlink() or source.stat().st_size != e['payload_size']:
                    raise ValueError('Recovered source size or type mismatch')
                with source.open('rb') as recovered:
                    for b in iter(lambda: recovered.read(BLOCK), b''):
                        h.update(b); adler = zlib.adler32(b, adler)
                e['validation'] = 'Recovered payload Adler and SHA-256; original stored and segment SHA-256 bound'
        finally:
            if writer:
                writer.close()
        e['payload_sha256'] = h.hexdigest()
        e['computed_adler32'] = adler & 0xffffffff
        if e['computed_adler32'] != e['adler32']:
            if destination:
                destination.unlink(missing_ok=True)
            raise ValueError(f"Adler mismatch/protected payload needs verified filter: {e['path']}")
        if extracted:
            p = Path(extracted) / e['path']
            if p.is_symlink() or p.stat().st_size != e['payload_size'] or digest(p) != e['payload_sha256']:
                raise ValueError(f"Extracted source differs from XP3: {e['path']}")
    if digest(path) != report['archive_sha256']:
        raise ValueError('Source archive changed during audit')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['inspect', 'audit', 'extract'])
    p.add_argument('--archive', required=True, type=Path)
    p.add_argument('--report', required=True, type=Path)
    p.add_argument('--extracted', type=Path)
    p.add_argument('--extractor', type=Path, help='Executable that recovered protected payloads; hash bound in report')
    p.add_argument('--destination', type=Path)
    args = p.parse_args()
    if args.command == 'extract' and not args.destination:
        p.error('extract requires --destination')
    for target in (args.report, args.destination):
        if target and (target.resolve() == args.archive.resolve() or args.archive.parent.resolve() in target.resolve().parents):
            p.error('Outputs must be external to the source archive directory')
    result = index(args.archive) if args.command == 'inspect' else audit(args.archive, args.extracted, extract=args.destination)
    if args.extractor:
        result['extractor_path'] = str(args.extractor.resolve())
        result['extractor_sha256'] = digest(args.extractor)
    if args.extracted or args.destination:
        result['extracted_path'] = str((args.extracted or args.destination).resolve())
    json_write(args.report, result)
    print(f"{args.command}: {len(result['entries'])} validated entries")


if __name__ == '__main__':
    main()
