#!/usr/bin/env python3
"""Convert extracted images to JXL payloads and build ordinary unencrypted XP3s.

Python 3.10+, Pillow and NumPy required. Defaults: q90/e8, 3 workers x 4 threads.
  python pipeline.py scan
  python pipeline.py run
  python pipeline.py convert --workers 3 --threads 4
  python pipeline.py build
  python pipeline.py verify output/bgimage.xp3
  python pipeline.py selftest

run = convert + build. Source files are only read. Each unpacked/<archive>
becomes its own output/<archive>.xp3; original paths/extensions are preserved.
TLG and unsupported images are copied unchanged. JXL requires a runtime hook.
Cache and atomic JSON manifest live under work/. Completed entries are reused
only when source, tool/script/config, payload, candidate and decoded hashes match.
Only RGB/RGBA PNG is converted; BMP/JPEG and palette/grayscale stay original.
Data conversion is restricted to evimage/**; rule/mask/label and ex_noize are
preserved. Original PNG color/ICC chunks are fed to cjxl and metadata hashes
are recorded. Alpha is lossless and pixel-tested; dimensions must match.
RGB error metrics include transparent pixels. source *_source.json files, if
present under ROOT, provide raw hash/adler validation and original stored cost.
Patch is excluded by default; original patch must retain its load priority.
Only smaller JXL candidates replace the original stored payload (both have the
same XP3 index overhead). Non-image payloads may use standard zlib segments.
16-bit PNG, animated images and unusual high-depth modes are preserved unchanged
rather than silently reducing precision. No TLG decoder is invoked.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zlib

from PIL import Image, __version__ as PILLOW_VERSION
import numpy as np

MAGIC = b"XP3\r\n \n\x1a\x8bg\x01"
HEADER_SIZE = len(MAGIC) + 8
CHUNK = 1024 * 1024
SCHEMA = 1
DEFAULT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = Path(os.environ.get("JXL_BIN", Path(shutil.which("cjxl.exe") or shutil.which("cjxl") or "cjxl.exe").parent))
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp"}
OTHER_IMAGE_EXTS = {".tlg", ".jxl", ".gif", ".webp", ".tif", ".tiff", ".ico", ".dds"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def digest_json(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def atomic_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, ensure_ascii=False, indent=2, allow_nan=False)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)


def load_manifest(path: Path):
    if not path.exists():
        return {"schema": SCHEMA, "entries": {}, "archives": {}}
    with path.open(encoding="utf-8") as f:
        value = json.load(f)
    if value.get("schema") != SCHEMA:
        raise ValueError("Unsupported manifest schema")
    return value


def safe_name(name: str):
    p = PurePosixPath(name)
    if (not name or "\\" in name or "\x00" in name or ":" in name
            or p.is_absolute() or any(x in ("", ".", "..") for x in name.split("/"))):
        raise ValueError(f"Unsafe archive path: {name!r}")
    return name


def check_names(names):
    exact, folded = set(), set()
    for name in names:
        safe_name(name)
        fold = name.casefold()
        if name in exact or fold in folded:
            raise ValueError(f"Duplicate/case-colliding path in one archive: {name}")
        exact.add(name)
        folded.add(fold)


def inventory(source: Path, archives):
    result = []
    for archive in archives:
        if safe_name(archive) != archive or "/" in archive:
            raise ValueError(f"Invalid archive name {archive!r}")
        folder = source / archive
        if not folder.is_dir() or folder.is_symlink():
            raise ValueError(f"Missing directory or symlink: {folder}")
        items = []
        for path in sorted(folder.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"Source symlink is not supported: {path}")
            if path.is_file():
                name = path.relative_to(folder).as_posix()
                safe_name(name)
                items.append((archive, name, path))
        check_names([x[1] for x in items])
        result.extend(items)
    return result


def source_costs(args):
    costs = {}
    for archive in args.archives:
        path = args.root / (archive + "_source.json")
        if path.exists():
            with path.open(encoding="utf-8") as f:
                data = json.load(f)
            for entry in data["entries"]:
                costs[archive + "/" + entry["name"]] = entry
    return costs


def png_metadata(path):
    records = []
    with path.open("rb") as stream:
        if exact_read(stream, 8) != b"\x89PNG\r\n\x1a\n":
            raise ValueError("Invalid PNG signature")
        while True:
            size, tag = struct.unpack(">I4s", exact_read(stream, 8))
            data = exact_read(stream, size)
            crc = struct.unpack(">I", exact_read(stream, 4))[0]
            if zlib.crc32(tag + data) & 0xffffffff != crc:
                raise ValueError("PNG CRC mismatch")
            if tag not in (b"IHDR", b"IDAT", b"IEND"):
                record = {"chunk": tag.decode("ascii"), "size": size,
                          "sha256": hashlib.sha256(data).hexdigest()}
                if tag in (b"tEXt", b"zTXt", b"iTXt"):
                    record["key"] = data.split(b"\0", 1)[0].decode("latin1")
                records.append(record)
            if tag == b"IEND":
                break
    return records


def config(args):
    cjxl = args.bin / "cjxl.exe"
    djxl = args.bin / "djxl.exe"
    for tool in (cjxl, djxl):
        if not tool.is_file():
            raise FileNotFoundError(tool)
    return {"schema": SCHEMA, "script_sha256": sha256(Path(__file__)),
            "cjxl_sha256": sha256(cjxl), "djxl_sha256": sha256(djxl),
            "pillow_version": PILLOW_VERSION, "quality": args.quality,
            "effort": args.effort, "encoder_threads": args.threads,
            "decoder_threads": args.threads, "alpha_distance": 0,
            "normalization": "8-bit RGB/RGBA PNG; JPEG pixel reencode",
            "nonimage_zlib": not args.no_compress,
            "zlib_version": zlib.ZLIB_RUNTIME_VERSION,
            "selection": "PNG RGB/RGBA only; data evimage only; skip rule/mask/label",
            "source_cost_files": {a: sha256(args.root / (a + "_source.json"))
                                  for a in args.archives if (args.root / (a + "_source.json")).exists()}}


def image_pixels(path: Path):
    with Image.open(path) as im:
        im.load()
        alpha = "A" in im.getbands() or "transparency" in im.info
        mode = "RGBA" if alpha else "RGB"
        rgb = im.convert(mode)
        return rgb.size, mode, rgb.tobytes()


def compare_images(source_png: Path, decoded: Path):
    size, mode, original = image_pixels(source_png)
    decoded_size, decoded_mode, pixels = image_pixels(decoded)
    if decoded_size != size or decoded_mode != mode:
        raise ValueError(f"Decoded geometry/mode changed: {size}/{mode} -> {decoded_size}/{decoded_mode}")
    channels = len(mode)
    a = np.frombuffer(original, dtype=np.uint8).reshape(-1, channels)
    b = np.frombuffer(pixels, dtype=np.uint8).reshape(-1, channels)
    alpha_equal = channels != 4 or bool(np.array_equal(a[:, 3], b[:, 3]))
    if not alpha_equal:
        raise ValueError("Alpha is not pixel-exact after JXL decode")
    # Row blocks keep peak temporary memory bounded for large backgrounds.
    count, absolute, squared, maximum = 0, 0, 0, 0
    for start in range(0, len(a), 262144):
        delta = a[start:start + 262144, :3].astype(np.int16) - b[start:start + 262144, :3].astype(np.int16)
        absolute += int(np.abs(delta).sum(dtype=np.int64))
        squared += int(np.square(delta.astype(np.int32)).sum(dtype=np.int64))
        maximum = max(maximum, int(np.abs(delta).max()))
        count += delta.size
    mse = squared / count
    return {"width": size[0], "height": size[1], "mode": mode,
            "source_pixel_sha256": hashlib.sha256(original).hexdigest(),
            "decoded_pixel_sha256": hashlib.sha256(pixels).hexdigest(),
            "alpha_equal": alpha_equal, "rgb_equal": squared == 0,
            "rgb_mae": absolute / count, "rgb_mse": mse,
            "rgb_max_error": maximum,
            "rgb_psnr_db": None if mse == 0 else 10 * math.log10(255 * 255 / mse),
            "psnr_infinite": mse == 0}


def normalize_image(source: Path, target: Path):
    # Preserve high-depth images; Pillow's convert would silently quantize them.
    if source.suffix.lower() == ".png":
        with source.open("rb") as f:
            header = f.read(29)
        if len(header) >= 25 and header[:8] == b"\x89PNG\r\n\x1a\n" and header[24] == 16:
            return "16-bit PNG preserved"
    with Image.open(source) as im:
        if getattr(im, "n_frames", 1) != 1:
            return "animated image preserved"
        if im.mode in {"I", "F"} or im.mode.startswith("I;16"):
            return f"high-depth mode {im.mode} preserved"
        im.load()
        alpha = "A" in im.getbands() or "transparency" in im.info
        if im.mode not in ("RGB", "RGBA"):
            return f"mode {im.mode} preserved for runtime semantics"
        # Feed original PNG with ICC/color chunks intact to cjxl. Preserve the
        # decoded output PNG as audit evidence; validation compares actual pixels.
        shutil.copyfile(source, target)
    return None


def run_tool(command):
    result = subprocess.run([str(x) for x in command], capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
    if result.returncode:
        raise RuntimeError(f"Tool failed ({result.returncode}): {' '.join(map(str, command))}\n"
                           f"{result.stdout[-4000:]}\n{result.stderr[-4000:]}")


def cache_paths(work: Path, key: str):
    folder = work / "items" / hashlib.sha256(key.encode("utf-8")).hexdigest()
    return folder, folder / "payload", folder / "candidate.jxl", folder / "decoded.png"


def resume_valid(entry, source_sha, signature, payload, candidate, decoded):
    if not entry or entry.get("status") != "complete":
        return False
    if entry.get("source_sha256") != source_sha or entry.get("config_sha256") != signature:
        return False
    try:
        if not payload.is_file() or sha256(payload) != entry["payload_sha256"]:
            return False
        if entry.get("encoded_sha256"):
            if sha256(candidate) != entry["encoded_sha256"] or sha256(decoded) != entry["decoded_png_sha256"]:
                return False
            size, mode, pixels = image_pixels(decoded)
            validation = entry["validation"]
            if (hashlib.sha256(pixels).hexdigest() != validation["decoded_pixel_sha256"]
                    or list(size) != [validation["width"], validation["height"]]
                    or mode != validation["mode"]):
                return False
        return True
    except (OSError, KeyError, ValueError):
        return False


def convert_one(item, args, signature, previous):
    archive, name, source = item
    key = archive + "/" + name
    folder, payload, candidate, decoded = cache_paths(args.work, key)
    original_sha = sha256(source)
    source_record = args.source_cost_map.get(key)
    if source_record and (original_sha != source_record["raw_sha256"] or not source_record.get("raw_adler_matches", False)):
        raise ValueError(f"Extracted source hash/adler differs from source index: {key}")
    if resume_valid(previous, original_sha, signature, payload, candidate, decoded):
        return key, previous, True
    folder.mkdir(parents=True, exist_ok=True)
    entry = {"archive": archive, "path": name, "status": "complete",
             "source_sha256": original_sha, "source_size": source.stat().st_size,
             "config_sha256": signature, "payload_path": str(payload.resolve()),
             "kind": "original", "reason": "non-image preserved"}
    payload_tmp = folder / "payload.tmp"
    normalized = folder / "normalized.png"
    try:
        if source.suffix.lower() == ".png":
            metadata = png_metadata(source)
            entry["png_metadata"] = metadata
            with Image.open(source) as image:
                icc = image.info.get("icc_profile")
            entry["icc_sha256"] = hashlib.sha256(icc).hexdigest() if icc else None
            lower = name.lower()
            skip = None
            if archive == "data" and not lower.startswith("evimage/"):
                skip = "data outside evimage preserved"
            elif "rule" in lower or "mask" in lower:
                skip = "rule/mask semantics preserved"
            elif lower.endswith("ex_noize.png"):
                skip = "nonstandard ICC noise image preserved"
            elif any(m.get("key", "").lower() == "label" or m["chunk"] in ("oFFs", "sCAL", "pCAL") for m in metadata):
                skip = "engine/position metadata preserved"
            if not skip:
                skip = normalize_image(source, normalized)
            if skip:
                entry["reason"] = skip
            else:
                encoded_tmp = folder / "candidate.tmp.jxl"
                decoded_tmp = folder / "decoded.tmp.png"
                run_tool([args.bin / "cjxl.exe", normalized, encoded_tmp,
                          "-q", args.quality, "-e", args.effort,
                          "--alpha_distance=0", f"--num_threads={args.threads}", "--quiet"])
                run_tool([args.bin / "djxl.exe", encoded_tmp, decoded_tmp,
                          f"--num_threads={args.threads}", "--bits_per_sample=8", "--quiet"])
                validation = compare_images(normalized, decoded_tmp)
                if args.quality == 100 and not validation["rgb_equal"]:
                    raise ValueError("q100 RGB is not pixel-exact")
                os.replace(encoded_tmp, candidate)
                os.replace(decoded_tmp, decoded)
                entry.update({"encoded_sha256": sha256(candidate),
                              "encoded_size": candidate.stat().st_size,
                              "decoded_png_sha256": sha256(decoded), "validation": validation})
                entry["original_xp3_stored_cost"] = source_record["stored"] if source_record else entry["source_size"]
                if entry["encoded_size"] < min(entry["source_size"], entry["original_xp3_stored_cost"]):
                    entry["kind"] = "jxl"
                    entry["reason"] = "JXL smaller than original stored segment"
                else:
                    entry["reason"] = "JXL not smaller than original stored segment"
        elif source.suffix.lower() == ".tlg":
            entry["reason"] = "TLG skipped; original preserved"
        shutil.copyfile(candidate if entry["kind"] == "jxl" else source, payload_tmp)
        # Catch concurrent source changes, including non-image copies.
        if sha256(source) != original_sha:
            raise ValueError(f"Source changed during conversion: {source}")
        if entry["kind"] == "original" and sha256(payload_tmp) != original_sha:
            raise ValueError(f"Original copy hash mismatch: {source}")
        entry["payload_sha256"] = sha256(payload_tmp)
        entry["payload_size"] = payload_tmp.stat().st_size
        os.replace(payload_tmp, payload)
        entry["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return key, entry, False
    finally:
        normalized.unlink(missing_ok=True)
        for temp_name in ("payload.tmp", "candidate.tmp.jxl", "decoded.tmp.png"):
            (folder / temp_name).unlink(missing_ok=True)


def prepare(args):
    items = inventory(args.source, args.archives)
    args.source_cost_map = source_costs(args)
    current_config = config(args)
    signature = digest_json(current_config)
    manifest = load_manifest(args.manifest)
    manifest.update({"config": current_config, "config_sha256": signature,
                     "source_root": str(args.source.resolve()), "selected_archives": args.archives,
                     "inventory": [a + "/" + n for a, n, _ in items]})
    atomic_json(args.manifest, manifest)
    failed, reused, changed = [], 0, 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(convert_one, item, args, signature,
                                   manifest["entries"].get(item[0] + "/" + item[1])): item for item in items}
        for future in concurrent.futures.as_completed(futures):
            item = futures[future]
            key = item[0] + "/" + item[1]
            try:
                key, entry, cached = future.result()
                manifest["entries"][key] = entry
                reused += cached
                changed += not cached
                print(f"{'reuse' if cached else entry['kind']:8} {key}", flush=True)
            except Exception as exc:
                failed.append(key)
                manifest["entries"][key] = {"archive": item[0], "path": item[1],
                                            "status": "error", "error": str(exc)}
                print(f"ERROR {key}: {exc}", file=sys.stderr, flush=True)
            atomic_json(args.manifest, manifest)
    print(f"Conversion complete: {changed} processed, {reused} reused, {len(failed)} failed.")
    if failed:
        raise RuntimeError(f"{len(failed)} conversion(s) failed; see manifest")
    return manifest


def chunk(tag: bytes, body: bytes) -> bytes:
    return tag + struct.pack("<Q", len(body)) + body


def exact_read(stream, count):
    data = stream.read(count)
    if len(data) != count:
        raise ValueError("Truncated XP3")
    return data


def bounded_zlib(data: bytes, expected: int) -> bytes:
    decoder = zlib.decompressobj()
    result = decoder.decompress(data, expected + 1)
    if len(result) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("Invalid zlib stream or decompressed size")
    return result


def parse_chunks(data: bytes):
    pos = 0
    while pos < len(data):
        if len(data) - pos < 12:
            raise ValueError("Truncated index chunk header")
        tag = data[pos:pos + 4]
        size = struct.unpack_from("<Q", data, pos + 4)[0]
        pos += 12
        if size > len(data) - pos:
            raise ValueError("Index chunk exceeds bounds")
        yield tag, data[pos:pos + size]
        pos += size


def verify_xp3(path: Path, expected=None, max_index=512 * 1024 * 1024):
    """Independent parser; no writer state or source files used to parse XP3."""
    file_size = path.stat().st_size
    records, ranges = [], []
    with path.open("rb") as stream:
        if exact_read(stream, len(MAGIC)) != MAGIC:
            raise ValueError("Invalid XP3 magic")
        index_offset = struct.unpack("<Q", exact_read(stream, 8))[0]
        if not HEADER_SIZE <= index_offset < file_size:
            raise ValueError("XP3 index offset out of bounds")
        stream.seek(index_offset)
        flags = exact_read(stream, 1)[0]
        if flags not in (0, 1):
            raise ValueError("Unsupported index continuation or compression flags")
        stored_size = struct.unpack("<Q", exact_read(stream, 8))[0]
        index_size = struct.unpack("<Q", exact_read(stream, 8))[0] if flags else stored_size
        if stored_size > max_index or index_size > max_index:
            raise ValueError("XP3 index exceeds configured safety limit")
        if stream.tell() + stored_size != file_size:
            raise ValueError("Index bounds do not end exactly at EOF")
        packed = exact_read(stream, stored_size)
        index = bounded_zlib(packed, index_size) if flags else packed
        for tag, body in parse_chunks(index):
            if tag != b"File":
                raise ValueError("Unexpected top-level XP3 chunk")
            children = {}
            for child, value in parse_chunks(body):
                if child in children:
                    raise ValueError("Duplicate file metadata chunk")
                children[child] = value
            if set(children) != {b"info", b"segm", b"adlr"}:
                raise ValueError("Missing/unexpected File chunks")
            info = children[b"info"]
            if len(info) < 22:
                raise ValueError("Truncated info")
            protection, original_size, archive_size, name_units = struct.unpack_from("<IQQH", info)
            if protection != 0 or len(info) != 22 + name_units * 2:
                raise ValueError("Protected flag or invalid UTF-16 name bounds")
            name = info[22:].decode("utf-16le", errors="strict")
            safe_name(name)
            segm = children[b"segm"]
            if not segm or len(segm) % 28 or len(children[b"adlr"]) != 4:
                raise ValueError("Invalid segment/adler chunk size")
            h, checksum, total_original, total_archive = hashlib.sha256(), 1, 0, 0
            for start in range(0, len(segm), 28):
                segment_flags, offset, original, stored = struct.unpack_from("<IQQQ", segm, start)
                if segment_flags not in (0, 1) or not HEADER_SIZE <= offset <= index_offset:
                    raise ValueError("Invalid segment flags/offset")
                if stored > index_offset - offset or (not segment_flags and stored != original):
                    raise ValueError("Segment bounds/size invalid")
                if stored:
                    ranges.append((offset, offset + stored, name))
                stream.seek(offset)
                remaining, count = stored, 0
                decoder = zlib.decompressobj() if segment_flags else None
                while remaining:
                    block = exact_read(stream, min(remaining, CHUNK))
                    remaining -= len(block)
                    if decoder:
                        # Bound memory even on hostile highly-compressed segments.
                        while True:
                            out = decoder.decompress(block, CHUNK)
                            count += len(out)
                            if count > original:
                                raise ValueError("Segment expands beyond declared size")
                            h.update(out)
                            checksum = zlib.adler32(out, checksum)
                            block = decoder.unconsumed_tail
                            if not block:
                                break
                    else:
                        count += len(block)
                        h.update(block)
                        checksum = zlib.adler32(block, checksum)
                if decoder and (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail):
                    raise ValueError("Truncated/trailing compressed segment")
                if count != original:
                    raise ValueError("Decoded segment size mismatch")
                total_original += original
                total_archive += stored
            checksum &= 0xffffffff
            if total_original != original_size or total_archive != archive_size:
                raise ValueError("File aggregate size mismatch")
            if checksum != struct.unpack("<I", children[b"adlr"])[0]:
                raise ValueError(f"Adler32 mismatch: {name}")
            record = {"path": name, "payload_sha256": h.hexdigest(), "payload_size": original_size,
                      "stored_size": archive_size, "adler32": checksum}
            if expected is not None:
                reference = expected.get(name)
                if reference is None or any(record[field] != reference[field]
                        for field in ("payload_sha256", "payload_size")):
                    raise ValueError(f"Unexpected path/payload hash/size: {name}")
            records.append(record)
    check_names([r["path"] for r in records])
    if expected is not None and set(expected) != {r["path"] for r in records}:
        raise ValueError("Archive inventory differs from manifest")
    ranges.sort()
    for left, right in zip(ranges, ranges[1:]):
        if left[1] > right[0]:
            raise ValueError(f"Overlapping payload segments: {left[2]} / {right[2]}")
    return {"path": str(path.resolve()), "archive_sha256": sha256(path),
            "archive_size": file_size, "index_offset": index_offset,
            "index_size": index_size, "file_count": len(records), "files": records}


def write_xp3(path: Path, entries, compress=True):
    check_names([e["path"] for e in entries])
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    file_chunks = []
    try:
        with temporary.open("w+b") as out:
            out.write(MAGIC + struct.pack("<Q", 0))
            for entry in sorted(entries, key=lambda x: x["path"]):
                payload = Path(entry["payload_path"])
                can_compress = compress and entry["kind"] != "jxl" and Path(entry["path"]).suffix.lower() not in IMAGE_EXTS | OTHER_IMAGE_EXTS
                with tempfile.TemporaryFile(dir=path.parent) as packed:
                    compressor = zlib.compressobj(6) if can_compress else None
                    h, adler, original_size = hashlib.sha256(), 1, 0
                    with payload.open("rb") as src:
                        for block in iter(lambda: src.read(CHUNK), b""):
                            h.update(block)
                            adler = zlib.adler32(block, adler)
                            original_size += len(block)
                            if compressor:
                                packed.write(compressor.compress(block))
                    if compressor:
                        packed.write(compressor.flush())
                    if h.hexdigest() != entry["payload_sha256"] or original_size != entry["payload_size"]:
                        raise ValueError(f"Cached payload changed: {entry['path']}")
                    compressed_size = packed.tell()
                    use_compressed = bool(compressor and compressed_size < original_size)
                    offset = out.tell()
                    stored_size = compressed_size if use_compressed else original_size
                    if use_compressed:
                        packed.seek(0)
                        shutil.copyfileobj(packed, out, CHUNK)
                    else:
                        with payload.open("rb") as src:
                            shutil.copyfileobj(src, out, CHUNK)
                name = entry["path"].encode("utf-16le")
                name_units = len(name) // 2
                if name_units > 65535:
                    raise ValueError("XP3 filename too long")
                info = struct.pack("<IQQH", 0, original_size, stored_size, name_units) + name
                segm = struct.pack("<IQQQ", int(use_compressed), offset, original_size, stored_size)
                body = chunk(b"info", info) + chunk(b"segm", segm) + chunk(b"adlr", struct.pack("<I", adler & 0xffffffff))
                file_chunks.append(chunk(b"File", body))
            index_offset = out.tell()
            index = b"".join(file_chunks)
            compressed_index = zlib.compress(index, 9)
            if len(compressed_index) < len(index):
                out.write(b"\x01" + struct.pack("<QQ", len(compressed_index), len(index)) + compressed_index)
            else:
                out.write(b"\x00" + struct.pack("<Q", len(index)) + index)
            out.seek(len(MAGIC))
            out.write(struct.pack("<Q", index_offset))
            out.flush()
            os.fsync(out.fileno())
        expected = {e["path"]: e for e in entries}
        report = verify_xp3(temporary, expected)
        os.replace(temporary, path)
        report["path"] = str(path.resolve())
        return report
    finally:
        temporary.unlink(missing_ok=True)


def build(args, manifest=None):
    manifest = manifest or load_manifest(args.manifest)
    signature = digest_json(config(args))
    items = inventory(args.source, args.archives)
    by_archive = {a: [] for a in args.archives}
    # Validate current source inventory and every cache before publishing anything.
    for archive, name, source in items:
        key = archive + "/" + name
        entry = manifest["entries"].get(key)
        _, payload, candidate, decoded = cache_paths(args.work, key)
        if not resume_valid(entry, sha256(source), signature, payload, candidate, decoded):
            raise ValueError(f"Missing/stale conversion entry: {key}; run convert first")
        by_archive[archive].append(entry)
    if set(manifest.get("inventory", [])) != {a + "/" + n for a, n, _ in items}:
        raise ValueError("Source inventory changed; run convert first")
    for archive, entries in by_archive.items():
        destination = args.output / (archive + ".xp3")
        build_signature = digest_json({"config": signature, "entries": [
            {"path": e["path"], "sha256": e["payload_sha256"], "size": e["payload_size"], "kind": e["kind"]}
            for e in sorted(entries, key=lambda e: e["path"])]})
        previous = manifest["archives"].get(archive, {})
        expected = {e["path"]: e for e in entries}
        if (previous.get("build_sha256") == build_signature and destination.is_file()
                and sha256(destination) == previous.get("archive_sha256")):
            report = verify_xp3(destination, expected)
            print(f"reuse archive {destination}", flush=True)
        else:
            report = write_xp3(destination, entries, not args.no_compress)
            print(f"built {destination}: {report['file_count']} files, {report['archive_size']} bytes", flush=True)
        report["build_sha256"] = build_signature
        manifest["archives"][archive] = report
        atomic_json(args.manifest, manifest)
    return manifest


def validate_locations(args):
    source = args.source.resolve()
    for target in (args.work.resolve(), args.output.resolve(), args.manifest.resolve()):
        if target == source or source in target.parents:
            raise ValueError(f"Outputs cannot be inside source directory: {target}")
    if "patch" in args.archives:
        raise ValueError("patch is excluded: retain the original archive and its load priority")
    if len(set(args.archives)) != len(args.archives):
        raise ValueError("Duplicate archive argument")
    if args.work.resolve() == args.output.resolve():
        raise ValueError("Work and output directories must differ")


def selftest(args):
    """Tiny isolated fixture tests; never access or launch the game."""
    with tempfile.TemporaryDirectory(prefix="jxl-pipeline-test-") as td:
        root = Path(td)
        source = root / "unpacked"
        for archive in ("bgimage", "patch"):
            (source / archive / "sub").mkdir(parents=True)
            (source / archive / "same.txt").write_bytes((archive + "\n").encode() * 5000)
            (source / archive / "empty.bin").write_bytes(b"")
        im = Image.new("RGBA", (96, 64))
        im.putdata([(x * 2 % 256, y * 3 % 256, (x + y) % 256, (x * 7 + y * 11) % 256)
                    for y in range(64) for x in range(96)])
        im.save(source / "bgimage" / "sub" / "unicode_\u03a9.png", compress_level=0)
        im.convert("RGB").save(source / "bgimage" / "rgb.png", compress_level=0)
        im.convert("RGB").save(source / "bgimage" / "picture.bmp")
        im.convert("RGB").save(source / "patch" / "picture.jpg", quality=95)
        (source / "patch" / "original.tlg").write_bytes(b"TLG-synthetic-placeholder")
        local = argparse.Namespace(**vars(args))
        local.source, local.work, local.output = source, root / "work", root / "output"
        local.manifest = local.work / "manifest.json"
        local.archives = ["bgimage", "patch"]
        before = {str(p): sha256(p) for _, _, p in inventory(source, local.archives)}
        manifest = prepare(local)
        manifest = build(local, manifest)
        stamp = {k: e["completed_at"] for k, e in manifest["entries"].items()}
        output_stamp = {p: p.stat().st_mtime_ns for p in local.output.glob("*.xp3")}
        again = prepare(local)
        assert stamp == {k: e["completed_at"] for k, e in again["entries"].items()}
        build(local, again)
        assert all(p.stat().st_mtime_ns == value for p, value in output_stamp.items())
        assert before == {str(p): sha256(p) for _, _, p in inventory(source, local.archives)}
        assert manifest["entries"]["bgimage/sub/unicode_\u03a9.png"]["validation"]["alpha_equal"]
        assert manifest["entries"]["bgimage/sub/unicode_\u03a9.png"]["kind"] == "jxl"
        assert manifest["entries"]["patch/original.tlg"]["kind"] == "original"
        # Corrupt candidate: resume must reject it and re-encode just that item.
        key = "bgimage/sub/unicode_\u03a9.png"
        _, payload, candidate, decoded = cache_paths(local.work, key)
        candidate.write_bytes(b"corrupt")
        assert not resume_valid(again["entries"][key], again["entries"][key]["source_sha256"],
                                again["config_sha256"], payload, candidate, decoded)
        repaired = prepare(local)
        assert sha256(candidate) == repaired["entries"][key]["encoded_sha256"]
        # Verify corruption detection and duplicate rejection independently.
        corrupt = root / "corrupt.xp3"
        shutil.copyfile(local.output / "bgimage.xp3", corrupt)
        with corrupt.open("r+b") as f:
            f.seek(len(MAGIC))
            f.write(struct.pack("<Q", 2 ** 63))
        try:
            verify_xp3(corrupt)
        except ValueError:
            pass
        else:
            raise AssertionError("Corrupt index offset was accepted")
        try:
            check_names(["same.txt", "same.txt"])
        except ValueError:
            pass
        else:
            raise AssertionError("Duplicate filenames were accepted")
        print("SELFTEST PASS: PNG/RGBA, BMP, JPEG, TLG copy, separate duplicate names, empty files, "
              "zlib/stored XP3, resume, cache corruption, index bounds, unchanged sources.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["scan", "run", "convert", "build", "verify", "selftest"])
    parser.add_argument("xp3", nargs="?", type=Path, help="XP3 path for verify")
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--source", type=Path, help="default: ROOT/unpacked")
    parser.add_argument("--work", type=Path, help="default: ROOT/work")
    parser.add_argument("--output", type=Path, help="default: ROOT/output")
    parser.add_argument("--manifest", type=Path, help="default: WORK/manifest.json")
    parser.add_argument("--bin", type=Path, default=DEFAULT_BIN, help="directory containing cjxl.exe/djxl.exe")
    parser.add_argument("--archives", nargs="+", default=["bgimage", "data", "fgimage"])
    parser.add_argument("--quality", "-q", type=float, default=90)
    parser.add_argument("--effort", "-e", type=int, default=8)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--threads", type=int, default=4, help="threads per encoder AND decoder")
    parser.add_argument("--no-compress", action="store_true", help="store non-image segments without zlib")
    parser.add_argument("--report", type=Path, help="optional JSON report for scan/verify")
    args = parser.parse_args(argv)
    args.source = args.source or args.root / "unpacked"
    args.work = args.work or args.root / "work"
    args.output = args.output or args.root / "output"
    args.manifest = args.manifest or args.work / "manifest.json"
    if not (0 <= args.quality <= 100 and 1 <= args.effort <= 10 and args.workers >= 1 and args.threads >= 1):
        parser.error("quality 0..100, effort 1..10, workers/threads >= 1 required")
    validate_locations(args)
    if args.command == "verify":
        if not args.xp3:
            parser.error("verify requires an XP3 path")
        report = verify_xp3(args.xp3)
        if args.manifest.exists():
            manifest = load_manifest(args.manifest)
            archive = args.xp3.stem
            saved = manifest.get("archives", {}).get(archive)
            if saved:
                expected = {e["path"]: e for e in manifest["entries"].values()
                            if e.get("archive") == archive and e.get("status") == "complete"}
                report = verify_xp3(args.xp3, expected)
                if report["archive_sha256"] != saved["archive_sha256"]:
                    raise ValueError("Archive SHA256 differs from manifest")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        if args.report:
            atomic_json(args.report, report)
    elif args.command == "scan":
        items = inventory(args.source, args.archives)
        report = {"source_root": str(args.source.resolve()), "archives": {}, "files": []}
        for archive, name, path in items:
            category = "image" if path.suffix.lower() in IMAGE_EXTS else "tlg-skipped" if path.suffix.lower() == ".tlg" else "copy"
            item = {"archive": archive, "path": name, "size": path.stat().st_size,
                    "source_sha256": sha256(path), "category": category}
            if path.suffix.lower() == ".png":
                item["png_metadata"] = png_metadata(path)
                with Image.open(path) as image:
                    item["mode"] = image.mode
                    item["dimensions"] = list(image.size)
                    icc = image.info.get("icc_profile")
                    item["icc_sha256"] = hashlib.sha256(icc).hexdigest() if icc else None
            report["files"].append(item)
            counts = report["archives"].setdefault(archive, {"image": 0, "tlg-skipped": 0, "copy": 0})
            counts[category] += 1
        print(json.dumps({"file_count": len(items), "archives": report["archives"]}, ensure_ascii=False, indent=2))
        if args.report:
            atomic_json(args.report, report)
    elif args.command == "selftest":
        selftest(args)
    elif args.command == "build":
        build(args)
    else:
        manifest = prepare(args)
        if args.command == "run":
            build(args, manifest)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
