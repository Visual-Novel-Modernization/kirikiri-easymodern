#!/usr/bin/env python3
"""
Automated compression and packaging pipeline for KiriKiri (krkrz) JXL and AV1.
Supports:
  1. Multi-process concurrent JXL compression (6 workers) with quality 90, effort 8, lossless alpha.
  2. TLG0-JXL hybrid container generation preserving tags chunks for character offsets and layer modes.
  3. HandBrakeCLI SVT-AV1 video transcoding (CRF 28 for 720p, CRF 32 for 1080p, Preset 5).
  4. XP3 unpacking and packing integration without roundtrip TLG validation failures.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

DEFAULT_CJXL = Path(os.environ.get("CJXL") or shutil.which("cjxl") or "cjxl")
DEFAULT_HANDBRAKE = Path(os.environ.get("HANDBRAKE") or shutil.which("HandBrakeCLI") or "HandBrakeCLI")
DEFAULT_XP3BRUTE = Path(os.environ.get("XP3BRUTE") or shutil.which("xp3brute") or "xp3brute")

TLG0_HEADER_MAGIC = b'TLG0.0\x00sds\x1a'


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_semantics_sensitive(name: str) -> bool:
    """Filter out images where compression could alter rendering semantics or game logic."""
    low = name.lower()
    patterns = [
        r'rule', r'mask', r'thum', r'thumb', r'ui', r'button',
        r'btn', r'icon', r'cursor', r'label', r'logo', r'font'
    ]
    return any(re.search(pat, low) for pat in patterns)


def parse_tlg0_container(data: bytes) -> tuple[bytes, bytes]:
    """Extract raw image stream and trailing chunks from a TLG0 container."""
    if len(data) < 15 or data[:11] != TLG0_HEADER_MAGIC:
        return data, b""
    raw_size = struct.unpack("<I", data[11:15])[0]
    raw_stream = data[15:15 + raw_size]
    chunks = data[15 + raw_size:]
    return raw_stream, chunks


def create_tlg0_hybrid_container(jxl_bytes: bytes, original_chunks: bytes) -> bytes:
    """Pack a JXL bitstream into a TLG0 container while preserving original chunks."""
    header = TLG0_HEADER_MAGIC
    raw_size = struct.pack("<I", len(jxl_bytes))
    return header + raw_size + jxl_bytes + original_chunks


def decode_tlg_to_png(tlg_path: Path, out_png: Path, xp3brute: Path = DEFAULT_XP3BRUTE) -> bool:
    """Decode TLG (or TLG0) to PNG using xp3brute decode-tlg."""
    cmd = [str(xp3brute), "decode-tlg", str(tlg_path), str(out_png)]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return res.returncode == 0 and out_png.exists() and out_png.stat().st_size > 0


def compress_png_to_jxl(png_path: Path, out_jxl: Path, cjxl: Path = DEFAULT_CJXL, quality: int = 90, effort: int = 8) -> bool:
    """Compress PNG to JXL using standard parameters."""
    cmd = [
        str(cjxl),
        "-q", str(quality),
        "-e", str(effort),
        "--alpha_distance=0",
        str(png_path),
        str(out_jxl)
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return res.returncode == 0 and out_jxl.exists() and out_jxl.stat().st_size > 0


def process_single_tlg(tlg_path: Path, out_tlg: Path, cjxl: Path, xp3brute: Path) -> dict:
    """Worker task: decode TLG, extract tags chunk, compress to JXL, build TLG0-JXL container."""
    result = {
        "file": str(tlg_path),
        "status": "failed",
        "orig_size": tlg_path.stat().st_size,
        "new_size": 0,
        "ratio": 0.0
    }
    
    if is_semantics_sensitive(tlg_path.name):
        shutil.copy2(tlg_path, out_tlg)
        result["status"] = "preserved_semantics"
        result["new_size"] = result["orig_size"]
        result["ratio"] = 1.0
        return result

    raw_tlg = tlg_path.read_bytes()
    _, original_chunks = parse_tlg0_container(raw_tlg)

    with tempfile.TemporaryDirectory(prefix="tlg_conv_") as temp:
        temp_dir = Path(temp)
        temp_png = temp_dir / "temp.png"
        temp_jxl = temp_dir / "temp.jxl"

        if not decode_tlg_to_png(tlg_path, temp_png, xp3brute):
            shutil.copy2(tlg_path, out_tlg)
            result["status"] = "decode_fallback"
            result["new_size"] = result["orig_size"]
            return result

        if not compress_png_to_jxl(temp_png, temp_jxl, cjxl):
            shutil.copy2(tlg_path, out_tlg)
            result["status"] = "cjxl_fallback"
            result["new_size"] = result["orig_size"]
            return result

        jxl_bytes = temp_jxl.read_bytes()
        hybrid_bytes = create_tlg0_hybrid_container(jxl_bytes, original_chunks)
        
        out_tlg.parent.mkdir(parents=True, exist_ok=True)
        out_tlg.write_bytes(hybrid_bytes)

        result["status"] = "compressed"
        result["new_size"] = len(hybrid_bytes)
        result["ratio"] = round(len(hybrid_bytes) / result["orig_size"], 4)
        return result


def process_single_png(png_path: Path, out_jxl: Path, cjxl: Path) -> dict:
    """Worker task: compress standard PNG to JXL."""
    result = {
        "file": str(png_path),
        "status": "failed",
        "orig_size": png_path.stat().st_size,
        "new_size": 0,
        "ratio": 0.0
    }

    if is_semantics_sensitive(png_path.name):
        shutil.copy2(png_path, out_jxl)
        result["status"] = "preserved_semantics"
        result["new_size"] = result["orig_size"]
        result["ratio"] = 1.0
        return result

    out_jxl.parent.mkdir(parents=True, exist_ok=True)
    if compress_png_to_jxl(png_path, out_jxl, cjxl):
        result["status"] = "compressed"
        result["new_size"] = out_jxl.stat().st_size
        result["ratio"] = round(result["new_size"] / result["orig_size"], 4)
    else:
        shutil.copy2(png_path, out_jxl)
        result["status"] = "fallback"
        result["new_size"] = result["orig_size"]
    return result


def batch_convert_images(input_dir: Path, output_dir: Path, max_workers: int = 6, cjxl: Path = DEFAULT_CJXL, xp3brute: Path = DEFAULT_XP3BRUTE):
    """Batch convert all images in input_dir with 6 concurrent worker processes."""
    input_dir = Path(input_dir).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    files_to_process = []
    for p in input_dir.rglob("*"):
        if p.is_file():
            ext = p.suffix.lower()
            rel = p.relative_to(input_dir)
            out_p = output_dir / rel
            if ext == ".tlg":
                files_to_process.append(("tlg", p, out_p))
            elif ext == ".png":
                files_to_process.append(("png", p, out_p))
            else:
                out_p.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, out_p)

    print(f"Total images to process: {len(files_to_process)} across {max_workers} worker processes")

    results = []
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for kind, in_p, out_p in files_to_process:
            if kind == "tlg":
                f = executor.submit(process_single_tlg, in_p, out_p, cjxl, xp3brute)
            else:
                f = executor.submit(process_single_png, in_p, out_p, cjxl)
            futures[f] = in_p

        done_count = 0
        total_orig = 0
        total_new = 0
        for f in as_completed(futures):
            res = f.result()
            results.append(res)
            done_count += 1
            total_orig += res["orig_size"]
            total_new += res["new_size"]
            if done_count % 50 == 0 or done_count == len(files_to_process):
                print(f"[{done_count}/{len(files_to_process)}] Processed {res['file']} -> {res['status']} ({res['ratio']:.2%})")

    overall_ratio = round(total_new / total_orig, 4) if total_orig else 1.0
    print(f"Conversion complete! Original: {total_orig / (1024*1024):.2f} MB, Compressed: {total_new / (1024*1024):.2f} MB (Ratio: {overall_ratio:.2%})")
    return results


def transcode_video_av1(video_in: Path, video_out: Path, handbrake: Path = DEFAULT_HANDBRAKE, height: int = 1080) -> bool:
    """Transcode a video stream to SVT-AV1 using HandBrakeCLI."""
    video_in = Path(video_in).resolve()
    video_out = Path(video_out).resolve()
    video_out.parent.mkdir(parents=True, exist_ok=True)

    crf = 28 if height <= 720 else 32
    cmd = [
        str(handbrake),
        "-i", str(video_in),
        "-o", str(video_out),
        "-e", "svt_av1",
        "-q", str(crf),
        "--encoder-preset", "5",
        "--aencoder", "copy"
    ]
    print(f"Transcoding {video_in.name} with SVT-AV1 (CRF {crf}, Preset 5)...")
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    success = res.returncode == 0 and video_out.exists() and video_out.stat().st_size > 0
    if success:
        print(f"Transcode succeeded: {video_out.name} ({video_out.stat().st_size / (1024*1024):.2f} MB)")
    else:
        print(f"Transcode failed: {res.stderr.decode(errors='replace')}")
    return success


def inject_startup_script(startup_tjs_path: Path):
    """Inject standard plugin link calls into startup.tjs."""
    startup_tjs_path = Path(startup_tjs_path).resolve()
    data = startup_tjs_path.read_bytes()
    
    # Check if XORed with 0xF8
    is_xored = False
    if len(data) >= 2 and data[0] == 0xd7 and data[1] == 0xd7:
        is_xored = True
        data = bytes([b ^ 0xF8 for b in data])

    text = ""
    encoding = "shift-jis"
    try:
        text = data.decode("shift-jis")
    except UnicodeDecodeError:
        try:
            text = data.decode("utf-16le")
            encoding = "utf-16le"
        except UnicodeDecodeError:
            text = data.decode("utf-8", errors="ignore")
            encoding = "utf-8"

    injection = '// Link JXL and AV1 GStreamer engine hooks\r\nPlugins.link("jxl_hook.dll"); Plugins.link("av1_gst_hook.dll");\r\n'
    if 'jxl_hook.dll' not in text:
        text = injection + text

    out_data = text.encode(encoding)
    if is_xored:
        out_data = bytes([b ^ 0xF8 for b in out_data])
    startup_tjs_path.write_bytes(out_data)
    print(f"Injected plugin link into {startup_tjs_path.name}")


def unpack_xp3_archive(archive_path: Path, output_dir: Path, xp3brute: Path = DEFAULT_XP3BRUTE):
    """Unpack raw archive entries using xp3brute with --tlg none."""
    cmd = [
        str(xp3brute),
        "unpack",
        str(archive_path),
        str(output_dir),
        "--tlg", "none",
        "--no-progress"
    ]
    print(f"Unpacking {archive_path.name} to {output_dir}...")
    subprocess.run(cmd, check=True)


def pack_xp3_archive(unpack_dir: Path, output_archive: Path, original_archive: Path, xp3brute: Path = DEFAULT_XP3BRUTE):
    """Pack directory back into XP3 using xp3brute with compact layout and original archive reference."""
    cmd = [
        str(xp3brute),
        "pack",
        str(unpack_dir),
        str(output_archive),
        "--source-archive", str(original_archive),
        "--compact-layout"
    ]
    print(f"Packing {unpack_dir.name} to {output_archive.name}...")
    subprocess.run(cmd, check=True)


def main():
    parser = argparse.ArgumentParser(description="KiriKiri JXL and AV1 compression and packaging pipeline.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_img = sub.add_parser("compress-images", help="Compress images in directory")
    p_img.add_argument("--in-dir", required=True, type=Path)
    p_img.add_argument("--out-dir", required=True, type=Path)
    p_img.add_argument("--workers", type=int, default=6)
    p_img.add_argument("--cjxl", type=Path, default=DEFAULT_CJXL)
    p_img.add_argument("--xp3brute", type=Path, default=DEFAULT_XP3BRUTE)

    p_vid = sub.add_parser("compress-video", help="Transcode video to AV1")
    p_vid.add_argument("--input", required=True, type=Path)
    p_vid.add_argument("--output", required=True, type=Path)
    p_vid.add_argument("--height", type=int, default=1080)
    p_vid.add_argument("--handbrake", type=Path, default=DEFAULT_HANDBRAKE)

    p_inj = sub.add_parser("inject-startup", help="Inject plugin links into startup.tjs")
    p_inj.add_argument("--startup", required=True, type=Path)

    p_pack = sub.add_parser("pack", help="Pack directory to XP3")
    p_pack.add_argument("--unpack-dir", required=True, type=Path)
    p_pack.add_argument("--output", required=True, type=Path)
    p_pack.add_argument("--source-archive", required=True, type=Path)
    p_pack.add_argument("--xp3brute", type=Path, default=DEFAULT_XP3BRUTE)

    args = parser.parse_args()

    if args.cmd == "compress-images":
        batch_convert_images(args.in_dir, args.out_dir, args.workers, args.cjxl, args.xp3brute)
    elif args.cmd == "compress-video":
        transcode_video_av1(args.input, args.output, args.handbrake, args.height)
    elif args.cmd == "inject-startup":
        inject_startup_script(args.startup)
    elif args.cmd == "pack":
        pack_xp3_archive(args.unpack_dir, args.output, args.source_archive, args.xp3brute)


if __name__ == "__main__":
    main()
