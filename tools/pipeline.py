#!/usr/bin/env python3
"""External-workspace PNG conversion, native proof and XP3 sidecar builder.

Commands: scan, convert, native, build, verify. Every command requires --work.
Source audit JSON reports are passed repeatedly with --audit. Native commands
require explicit --hook, --selftest and --djxl-x86. No command launches a game.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import zlib
from PIL import Image, __version__ as PIL_VERSION
import numpy as np
import xp3

ROOT = Path(__file__).resolve().parents[1]


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def external(path, sources=()):
    path = Path(path).resolve()
    if path == ROOT or ROOT in path.parents:
        raise ValueError('Runtime outputs must be outside the repository')
    for source in sources:
        source = Path(source).resolve()
        if path == source or source in path.parents:
            raise ValueError('Outputs must be outside source directories')
    return path


@contextmanager
def lock(work):
    work.mkdir(parents=True, exist_ok=True)
    path = work / 'pipeline.lock'
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise ValueError('Another pipeline owns this workspace; stale locks require manual inspection')
    try:
        os.write(fd, str(os.getpid()).encode()); os.close(fd)
        yield
    finally:
        path.unlink()


def execute(command):
    result = subprocess.run([str(x) for x in command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise ValueError(result.stderr.decode(errors='replace') or result.stdout.decode(errors='replace'))
    stdout = result.stdout.decode(errors='strict')
    return stdout if stdout.strip() else result.stderr.decode(errors='replace')


def pe_x86(path):
    with Path(path).open('rb') as f:
        if f.read(2) != b'MZ':
            raise ValueError('Native binary is not PE')
        f.seek(60); offset = struct.unpack('<I', f.read(4))[0]; f.seek(offset)
        if f.read(4) != b'PE\0\0' or struct.unpack('<H', f.read(2))[0] != 0x14c:
            raise ValueError('Native binary must be x86 PE')


def version(path):
    text = execute([path, '--version'])
    match = re.search(r'\b(\d+\.\d+\.\d+)\b', text)
    if not match:
        raise ValueError('Cannot determine decoder version')
    return match.group(1)


def native_tools(args):
    for path in (args.hook, args.selftest, args.djxl_x86):
        if path is None:
            raise ValueError('Native binding requires --hook, --selftest, --djxl-x86')
        pe_x86(path)
    info = json.loads(execute([args.selftest, '--version']))
    decoder_version = version(args.djxl_x86)
    if info['version'] != decoder_version:
        raise ValueError('Native decoder and x86 djxl versions differ')
    parts = [int(p) for p in decoder_version.split('.')]
    if info['decoder_version'] != parts[0] * 1000000 + parts[1] * 1000 + parts[2]:
        raise ValueError('Native numeric decoder version mismatch')
    return {'hook_sha256': xp3.digest(args.hook), 'selftest_sha256': xp3.digest(args.selftest),
            'djxl_x86_sha256': xp3.digest(args.djxl_x86), 'decoder_version': decoder_version,
            'native_version': info['decoder_version']}


def png_selected(archive, name, source):
    low = name.lower()
    components = low.split('/')
    if not low.endswith('.png'):
        return False, 'Unsupported format'
    if any(re.search(r'(rule|mask|thum|thumb|ui|button|icon|cursor|label|logo)', p) for p in components):
        return False, 'Semantics-sensitive path'
    if archive == 'data':
        allowed = bool(re.fullmatch(r'bgimage/bg\d+[a-z0-9]*_\d+\.png', low) or
                       re.fullmatch(r'evimage/ev[a-z0-9_]+\.png', low))
    elif archive == 'adult':
        allowed = bool(re.fullmatch(r'ev[a-z0-9_]+\.png', low))
    else:
        allowed = False
    if not allowed:
        return False, 'Outside audited backgrounds and CG categories'
    data = source.read_bytes()
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('PNG path lacks PNG signature')
    p, header, animated, ended = 8, None, False, False
    while p < len(data):
        if len(data) - p < 12:
            raise ValueError('Truncated PNG')
        n, tag = struct.unpack_from('>I4s', data, p); p += 8
        if n > len(data) - p - 4:
            raise ValueError('PNG chunk bounds')
        body = data[p:p+n]; p += n
        crc = struct.unpack_from('>I', data, p)[0]; p += 4
        if zlib.crc32(tag + body) & 0xffffffff != crc:
            raise ValueError('PNG CRC mismatch')
        if tag == b'IHDR':
            if header is not None or n != 13:
                raise ValueError('Invalid PNG IHDR')
            header = struct.unpack('>IIBBBBB', body)
        if tag == b'acTL':
            animated = True
        if tag == b'IEND':
            ended = True; break
    if not ended or p != len(data) or header is None:
        raise ValueError('Invalid PNG termination')
    if header[2] != 8 or header[3] not in (2, 6) or animated:
        return False, 'Palette, grayscale, high-depth or animated PNG'
    with Image.open(source) as im:
        im.load()
        if im.mode not in ('RGB', 'RGBA') or getattr(im, 'n_frames', 1) != 1 or 'transparency' in im.info:
            return False, 'Nonordinary image mode/transparency'
        if im.width < 640 or im.height < 360:
            return False, 'Small auxiliary image'
    return True, 'Audited background or CG RGB/RGBA PNG'


def sources(args):
    result, audits = {}, {}
    for report_path in args.audit:
        report = json.loads(report_path.read_text(encoding='utf-8'))
        archive = Path(report['archive_path']).stem
        if archive not in ('data', 'adult') or archive in audits or 'extracted_path' not in report:
            raise ValueError('Audit needs unique data/adult and extracted_path')
        if xp3.digest(report['archive_path']) != report['archive_sha256']:
            raise ValueError('Original archive changed since audit')
        if not report.get('extractor_sha256') and any(e['protection'] for e in report['entries']):
            raise ValueError('Protected source lacks extractor provenance')
        if report.get('extractor_path') and xp3.digest(report['extractor_path']) != report['extractor_sha256']:
            raise ValueError('Extractor changed since audit')
        audits[archive] = {'path': str(report_path.resolve()), 'sha256': xp3.digest(report_path),
                           'archive_sha256': report['archive_sha256']}
        folder = Path(report['extracted_path'])
        expected = set()
        for entry in report['entries']:
            name = xp3.safe(entry['path']); expected.add(name)
            source = folder / name
            if any(p.is_symlink() for p in (source, *source.parents)):
                raise ValueError('Source path contains symlink ancestor')
            if source.is_symlink() or xp3.digest(source) != entry['payload_sha256'] or source.stat().st_size != entry['payload_size']:
                raise ValueError(f'Stale extracted payload: {archive}/{name}')
            key = archive + '/' + name
            chosen, reason = png_selected(archive, name, source)
            result[key] = {'archive': archive, 'path': name, 'source_path': str(source.resolve()),
                           'source_sha256': entry['payload_sha256'], 'source_size': entry['payload_size'],
                           'source_adler32': entry['adler32'], 'stored_size': entry['stored_size'],
                           'selected': chosen, 'reason': reason}
        actual = set()
        for p in folder.rglob('*'):
            if p.is_symlink():
                raise ValueError('Source tree contains symlink')
            if p.is_file():
                actual.add(p.relative_to(folder).as_posix())
        if actual != expected:
            raise ValueError('Extracted tree differs from audited exact inventory')
    if not result:
        raise ValueError('At least one --audit is required')
    return result, audits


def config(args):
    if args.cjxl is None:
        raise ValueError('--cjxl is required')
    return {'schema': 1, 'quality': 90, 'effort': 8, 'alpha_distance': 0, 'threads': args.threads,
            'cjxl_sha256': xp3.digest(args.cjxl), 'cjxl_version': version(args.cjxl),
            'pipeline_sha256': xp3.digest(Path(__file__)), 'xp3_tool_sha256': xp3.digest(Path(xp3.__file__)),
            'pillow_version': PIL_VERSION, 'selection': 'data BG/EV and adult EV; ordinary 8-bit RGB/RGBA; conservative auxiliaries excluded'}


def bgra(path):
    with Image.open(path) as image:
        image.load(); a = np.asarray(image.convert('RGBA'), dtype=np.uint8)
        return image.size, a[:, :, [2, 1, 0, 3]].tobytes()


def current_manifest(args):
    manifest = json.loads((args.work / 'manifest.json').read_text(encoding='utf-8'))
    inventory, audits = sources(args)
    if manifest['audits'] != audits or set(manifest['entries']) != set(inventory):
        raise ValueError('Manifest does not match current exact source inventory/audit')
    if manifest['config'] != config(args):
        raise ValueError('Stale manifest configuration/tool binding')
    for key, source in inventory.items():
        entry = manifest['entries'][key]
        if any(entry[k] != v for k, v in source.items()):
            raise ValueError(f'Stale source/selection: {key}')
        if entry.get('status') != 'complete' or xp3.digest(entry['payload_path']) != entry['payload_sha256']:
            raise ValueError(f'Missing/stale payload: {key}')
        if Path(entry['payload_path']).stat().st_size != entry['payload_size']:
            raise ValueError('Payload size changed')
        if entry['kind'] == 'copy' and entry['payload_sha256'] != entry['source_sha256']:
            raise ValueError('Untouched payload changed')
    return manifest


def convert(args):
    inventory, audits = sources(args)
    settings = config(args)
    manifest_path = args.work / 'manifest.json'
    previous = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    old_entries = previous.get('entries', {}) if previous.get('config') == settings and previous.get('audits') == audits else {}
    manifest = {'schema': 1, 'config': settings, 'audits': audits, 'entries': inventory}
    xp3.json_write(manifest_path, manifest)
    def one(item):
        key, source = item
        old = old_entries.get(key)
        if old and all(old.get(k) == v for k, v in source.items()) and old.get('status') == 'complete':
            if Path(old['payload_path']).is_file() and xp3.digest(old['payload_path']) == old['payload_sha256']:
                return key, old
        entry = dict(source)
        directory = args.work / 'cache' / hashlib.sha256(key.encode()).hexdigest()
        directory.mkdir(parents=True, exist_ok=True)
        original = Path(entry['source_path']); payload = original; kind = 'copy'
        if entry['selected']:
            candidate = directory / 'candidate.jxl'
            execute([args.cjxl, original, candidate, '-q', '90', '-e', '8', '--alpha_distance=0',
                     '--num_threads=' + str(args.threads)])
            if candidate.stat().st_size < entry['stored_size']:
                payload, kind = candidate, 'jxl'
            else:
                entry['retention_reason'] = 'Candidate has no stored-size benefit'
        entry.update(status='complete', kind=kind, payload_path=str(payload.resolve()),
                     payload_sha256=xp3.digest(payload), payload_size=payload.stat().st_size)
        return key, entry
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for key, entry in pool.map(one, inventory.items()):
            manifest['entries'][key] = entry
            xp3.json_write(manifest_path, manifest)
            print(entry['kind'], key, flush=True)


def native(args):
    manifest = current_manifest(args)
    tools = native_tools(args)
    proofs = {}
    for key, entry in manifest['entries'].items():
        if entry['kind'] != 'jxl':
            continue
        directory = args.work / 'native' / hashlib.sha256(key.encode()).hexdigest()
        directory.mkdir(parents=True, exist_ok=True)
        raw, png = directory / 'callback.bgra', directory / 'djxl.png'
        info = json.loads(execute([args.selftest, '--bgra', entry['payload_path'], raw, '--hook', args.hook]))
        execute([args.djxl_x86, entry['payload_path'], png, '--num_threads=' + str(args.threads)])
        size, expected = bgra(png); source_size, original = bgra(entry['source_path'])
        actual = raw.read_bytes()
        if size != source_size or actual != expected or len(actual) != size[0] * size[1] * 4:
            raise ValueError(f'Native and x86 djxl BGRA differ: {key}')
        if actual[3::4] != original[3::4]:
            raise ValueError(f'Source alpha differs: {key}')
        if any(info.get(k) is not True for k in ('callbacks', 'dll_handler', 'png_fallback', 'stream_restored')):
            raise ValueError('Native callback/handler tests failed')
        if (info.get('callback_sha256') != xp3.digest(raw) or info.get('payload_sha256') != entry['payload_sha256']
                or info.get('width') != size[0] or info.get('height') != size[1] or info.get('commits') != size[1]
                or info.get('version') != tools['decoder_version'] or info.get('decoder_version') != tools['native_version']):
            raise ValueError('Native callback output binding mismatch')
        src_rgb = np.frombuffer(original, dtype=np.uint8).reshape(-1, 4)[:, :3].astype(np.int16)
        decoded_rgb = np.frombuffer(actual, dtype=np.uint8).reshape(-1, 4)[:, :3].astype(np.int16)
        delta = decoded_rgb - src_rgb
        mse = float(np.mean(delta.astype(np.float64) ** 2))
        alpha = np.frombuffer(original, dtype=np.uint8).reshape(-1, 4)[:, 3].astype(np.float64) / 255
        visible = float(np.sum(np.abs(delta) * alpha[:, None]) / (3 * alpha.sum())) if alpha.sum() else 0.0
        metrics = {'rgb_mae': float(np.abs(delta).mean()), 'rgb_mse': mse,
                   'rgb_psnr_db': None if mse == 0 else float(10 * np.log10(255 ** 2 / mse)),
                   'rgb_max_error': int(np.abs(delta).max()), 'visible_alpha_weighted_mae': visible,
                   'hidden_rgb_included': True}
        proofs[key] = {'source_sha256': entry['source_sha256'], 'payload_sha256': entry['payload_sha256'],
                       'quality_metrics': metrics,
                       'callback_sha256': xp3.digest(raw), 'reference_bgra_sha256': hashlib.sha256(expected).hexdigest(),
                       'source_alpha_sha256': hashlib.sha256(original[3::4]).hexdigest(),
                       'raw_path': str(raw.resolve()), 'png_path': str(png.resolve()), 'png_sha256': xp3.digest(png), 'info': info}
    binding = {'schema': 1, 'manifest_sha256': canonical(manifest), 'tools': tools, 'entries': proofs}
    xp3.json_write(args.work / 'native-binding.json', binding)


def binding(args, manifest):
    proof = json.loads((args.work / 'native-binding.json').read_text())
    if proof['manifest_sha256'] != canonical(manifest) or proof['tools'] != native_tools(args):
        raise ValueError('Missing/stale native manifest or binary binding')
    required = {k for k, e in manifest['entries'].items() if e['kind'] == 'jxl'}
    if set(proof['entries']) != required:
        raise ValueError('Native evidence differs from current manifest keys')
    for key in required:
        e, p = manifest['entries'][key], proof['entries'][key]
        if p['source_sha256'] != e['source_sha256'] or p['payload_sha256'] != e['payload_sha256']:
            raise ValueError('Native evidence payload binding differs')
        if xp3.digest(p['raw_path']) != p['callback_sha256'] or xp3.digest(p['png_path']) != p['png_sha256']:
            raise ValueError('Native evidence outputs changed')
        size, reference = bgra(p['png_path']); source_size, original = bgra(e['source_path'])
        raw = Path(p['raw_path']).read_bytes()
        if raw != reference or size != source_size or raw[3::4] != original[3::4]:
            raise ValueError('Native pixel evidence failed revalidation')
    return proof


def chunk(tag, b):
    return tag + struct.pack('<Q', len(b)) + b


def write_archive(path, entries):
    tmp = path.with_name(path.name + '.tmp')
    if path.exists() or tmp.exists():
        raise ValueError('Build refuses to overwrite existing output or temporary archive')
    index = []
    try:
        with tmp.open('xb') as out:
            out.write(xp3.MAGIC + struct.pack('<Q', 0))
            for e in entries:
                offset = out.tell(); adler = 1; h = hashlib.sha256(); n = 0
                with Path(e['payload_path']).open('rb') as src:
                    for b in iter(lambda: src.read(xp3.BLOCK), b''):
                        out.write(b); adler = zlib.adler32(b, adler); h.update(b); n += len(b)
                if h.hexdigest() != e['payload_sha256'] or n != e['payload_size']:
                    raise ValueError('Payload changed during build')
                stored, compressed = n, False
                if e.get('kind') == 'copy' and Path(e['path']).suffix.lower() not in ('.png', '.tlg', '.ogg', '.mpg', '.wmv', '.pimg'):
                    with tempfile.TemporaryFile(dir=path.parent) as packed_stream:
                        compressor = zlib.compressobj(6)
                        with Path(e['payload_path']).open('rb') as src:
                            for b in iter(lambda: src.read(xp3.BLOCK), b''):
                                packed_stream.write(compressor.compress(b))
                        packed_stream.write(compressor.flush())
                        if packed_stream.tell() < n:
                            stored = packed_stream.tell(); compressed = True
                            out.seek(offset); out.truncate(); packed_stream.seek(0)
                            shutil.copyfileobj(packed_stream, out, xp3.BLOCK)
                name = e['path'].encode('utf-16le')
                body = chunk(b'info', struct.pack('<IQQH', 0, n, stored, len(name)//2) + name)
                body += chunk(b'segm', struct.pack('<IQQQ', int(compressed), offset, n, stored))
                body += chunk(b'adlr', struct.pack('<I', adler & 0xffffffff))
                index.append(chunk(b'File', body))
            offset = out.tell(); raw = b''.join(index); packed = zlib.compress(raw, 9)
            out.write(b'\1' + struct.pack('<QQ', len(packed), len(raw)) + packed)
            out.seek(11); out.write(struct.pack('<Q', offset)); out.flush(); os.fsync(out.fileno())
        report = xp3.audit(tmp)
        expected = {e['path']: e['payload_sha256'] for e in entries}
        if {e['path']: e['payload_sha256'] for e in report['entries']} != expected:
            raise ValueError('Rebuilt archive differs from exact manifest')
        tmp.replace(path)
        report['archive_path'] = str(path.resolve())
        return report
    finally:
        tmp.unlink(missing_ok=True)


def build(args):
    manifest = current_manifest(args); binding(args, manifest)
    if args.output is None:
        raise ValueError('build requires --output')
    output = external(args.output, [Path(e['source_path']).parents[len(Path(e['path']).parts)-1] for e in manifest['entries'].values()])
    output.mkdir(parents=True, exist_ok=True)
    for archive in manifest['audits']:
        entries = [e for e in manifest['entries'].values() if e['archive'] == archive]
        report = write_archive(output / (archive + '.xp3'), entries)
        report['manifest_sha256'] = canonical(manifest)
        xp3.json_write(output / (archive + '.verification.json'), report)


def verify(args):
    manifest = current_manifest(args); binding(args, manifest)
    if args.output is None:
        raise ValueError('verify requires --output')
    for archive in manifest['audits']:
        report = xp3.audit(args.output / (archive + '.xp3'))
        expected = {e['path']: (e['payload_sha256'], e['payload_size']) for e in manifest['entries'].values() if e['archive'] == archive}
        actual = {e['path']: (e['payload_sha256'], e['payload_size']) for e in report['entries']}
        if actual != expected:
            raise ValueError('Archive inventory or exact payload differs from current manifest')
        print('Verified current manifest:', archive, len(actual))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['scan', 'convert', 'native', 'build', 'verify'])
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--audit', type=Path, action='append', default=[])
    p.add_argument('--output', type=Path)
    for tool in ('cjxl', 'hook', 'selftest', 'djxl-x86'):
        p.add_argument('--' + tool, type=Path)
    p.add_argument('--workers', type=int, default=3, choices=range(1, 4))
    p.add_argument('--threads', type=int, default=4, choices=range(1, 5))
    args = p.parse_args(); args.work = external(args.work)
    with lock(args.work):
        if args.command == 'scan':
            inventory, audits = sources(args)
            xp3.json_write(args.work / 'selection.json', {'audits': audits, 'entries': inventory})
            print('Selected', sum(e['selected'] for e in inventory.values()), 'of', len(inventory))
        else:
            globals()[args.command](args)


if __name__ == '__main__':
    main()
