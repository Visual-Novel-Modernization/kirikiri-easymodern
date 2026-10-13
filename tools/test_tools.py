#!/usr/bin/env python3
"""Synthetic structural and fail-closed tests; no original game access."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zlib
from PIL import Image
import pipeline
import xp3


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def fixture(self):
        source = self.root / 'original.bin'
        source.write_bytes(b'untouched payload\0' * 100)
        entry = {'path': 'folder/payload.bin', 'payload_path': str(source),
                 'payload_sha256': xp3.digest(source), 'payload_size': source.stat().st_size}
        archive = self.root / 'fixture.xp3'
        pipeline.write_archive(archive, [entry])
        return archive, entry

    def test_roundtrip_and_corruption(self):
        archive, entry = self.fixture()
        report = xp3.audit(archive)
        self.assertEqual(report['entries'][0]['payload_sha256'], entry['payload_sha256'])
        self.assertEqual(report['entries'][0]['path'], entry['path'])
        data = bytearray(archive.read_bytes()); data[20] ^= 1; archive.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'Adler mismatch'):
            xp3.audit(archive)

    def test_continued_index(self):
        archive, entry = self.fixture()
        data = archive.read_bytes(); old = struct.unpack_from('<Q', data, 11)[0]
        # Move the complete archive body behind a zero-size continuation descriptor.
        records = xp3.index(archive)['entries']
        body = bytearray(data[19:])
        packed_index = data[old:]
        index_body = zlib.decompress(packed_index[17:])
        index_body = bytearray(index_body)
        # Segment offset is in the segm child's body; use chunk parsing to rebuild.
        rebuilt = []
        for tag, filebody in xp3.chunks(index_body):
            children = []
            for child, value in xp3.chunks(filebody):
                if child == b'segm':
                    flag, off, n, s = struct.unpack('<IQQQ', value)
                    value = struct.pack('<IQQQ', flag, off + 17, n, s)
                children.append(pipeline.chunk(child, value))
            rebuilt.append(pipeline.chunk(tag, b''.join(children)))
        raw = b''.join(rebuilt); packed = zlib.compress(raw)
        newoff = old + 17
        archive.write_bytes(xp3.MAGIC + struct.pack('<Q', 19) + b'\x80' + struct.pack('<QQ', 0, newoff)
                            + data[19:old] + b'\1' + struct.pack('<QQ', len(packed), len(raw)) + packed)
        self.assertEqual(xp3.audit(archive)['entries'][0]['payload_sha256'], entry['payload_sha256'])

    def test_paths(self):
        for name in ('../bad', '/bad', 'x\\bad', 'a//b', 'a/CON.txt', 'a./b', 'x\0'):
            with self.assertRaises(ValueError):
                xp3.safe(name)

    def test_selection(self):
        p = self.root / 'picture.png'
        Image.new('RGBA', (640, 360), (1, 2, 3, 4)).save(p)
        self.assertTrue(pipeline.png_selected('data', 'bgimage/BG000_00.png', p)[0])
        self.assertTrue(pipeline.png_selected('adult', 'EVH01_01.png', p)[0])
        for archive, name in [('data', 'rule/mask.png'), ('data', 'image/button.png'),
                              ('adult', 'thum_EVH01.png'), ('data', 'bgimage/blackline.png')]:
            self.assertFalse(pipeline.png_selected(archive, name, p)[0])
        Image.new('P', (640, 360)).save(p)
        self.assertFalse(pipeline.png_selected('adult', 'EVH01_01.png', p)[0])
        Image.new('L', (640, 360)).save(p)
        self.assertFalse(pipeline.png_selected('adult', 'EVH01_01.png', p)[0])

    def test_lock(self):
        with pipeline.lock(self.root / 'work'):
            with self.assertRaises(ValueError):
                with pipeline.lock(self.root / 'work'):
                    pass
        self.assertFalse((self.root / 'work' / 'pipeline.lock').exists())

    def test_missing_native_proof(self):
        from types import SimpleNamespace
        with self.assertRaises(FileNotFoundError):
            pipeline.binding(SimpleNamespace(work=self.root), {'entries': {}})


if __name__ == '__main__':
    unittest.main()
