from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from ctypes.util import find_library


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("imagectl", REPOSITORY_ROOT / "tools" / "imagectl.py")
assert SPEC is not None and SPEC.loader is not None
imagectl = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = imagectl
SPEC.loader.exec_module(imagectl)


def sparse_image_bytes(block_size: int, chunks: list[tuple[int, int, bytes]]) -> bytes:
    total_blocks = sum(
        blocks for kind, blocks, _payload in chunks if kind != imagectl.CHUNK_CRC32
    )
    output = bytearray(
        imagectl.SPARSE_HEADER.pack(
            imagectl.SPARSE_MAGIC,
            1,
            0,
            imagectl.SPARSE_HEADER.size,
            imagectl.SPARSE_CHUNK_HEADER.size,
            block_size,
            total_blocks,
            len(chunks),
            0,
        )
    )
    for kind, blocks, payload in chunks:
        output.extend(
            imagectl.SPARSE_CHUNK_HEADER.pack(
                kind,
                0,
                blocks,
                imagectl.SPARSE_CHUNK_HEADER.size + len(payload),
            )
        )
        output.extend(payload)
    return bytes(output)


def lp_geometry(metadata_max_size: int = 4096, slots: int = 1) -> bytes:
    geometry = bytearray(
        imagectl.LP_GEOMETRY.pack(
            imagectl.LP_GEOMETRY_MAGIC,
            imagectl.LP_GEOMETRY.size,
            bytes(32),
            metadata_max_size,
            slots,
            4096,
        )
    )
    geometry[8:40] = hashlib.sha256(geometry).digest()
    return bytes(geometry)


def lp_metadata(device_size: int, extent_sector: int) -> bytes:
    partition = imagectl.LP_PARTITION.pack(b"system_a", 1, 0, 1, 0)
    extent = imagectl.LP_EXTENT.pack(8, imagectl.LP_TARGET_LINEAR, extent_sector, 0)
    group = imagectl.LP_GROUP.pack(b"main_a", 0, 4096)
    device = imagectl.LP_BLOCK_DEVICE.pack(
        2048,
        1024 * 1024,
        0,
        device_size,
        b"super",
        0,
    )
    tables = partition + extent + group + device
    header = bytearray(128)
    imagectl.LP_HEADER_PREFIX.pack_into(
        header,
        0,
        imagectl.LP_HEADER_MAGIC,
        imagectl.LP_MAJOR_VERSION,
        0,
        len(header),
        bytes(32),
        len(tables),
        hashlib.sha256(tables).digest(),
    )
    offsets = (0, len(partition), len(partition) + len(extent), len(partition) + len(extent) + len(group))
    descriptors = (
        (offsets[0], 1, imagectl.LP_PARTITION.size),
        (offsets[1], 1, imagectl.LP_EXTENT.size),
        (offsets[2], 1, imagectl.LP_GROUP.size),
        (offsets[3], 1, imagectl.LP_BLOCK_DEVICE.size),
    )
    for index, descriptor in enumerate(descriptors):
        imagectl.LP_DESCRIPTOR.pack_into(
            header,
            80 + index * imagectl.LP_DESCRIPTOR.size,
            *descriptor,
        )
    header[12:44] = hashlib.sha256(header).digest()
    return bytes(header) + tables


def synthetic_super_sparse() -> tuple[bytes, bytes]:
    block_size = 4096
    raw_size = 2 * 1024 * 1024
    first_region = bytearray(8 * block_size)
    geometry = lp_geometry()
    first_region[imagectl.LP_RESERVED_BYTES : imagectl.LP_RESERVED_BYTES + len(geometry)] = geometry
    backup_geometry_offset = imagectl.LP_RESERVED_BYTES + imagectl.LP_GEOMETRY_SIZE
    first_region[backup_geometry_offset : backup_geometry_offset + len(geometry)] = geometry
    metadata = lp_metadata(raw_size, 2048)
    primary_metadata_offset = imagectl.LP_RESERVED_BYTES + 2 * imagectl.LP_GEOMETRY_SIZE
    backup_metadata_offset = primary_metadata_offset + 4096
    first_region[primary_metadata_offset : primary_metadata_offset + len(metadata)] = metadata
    first_region[backup_metadata_offset : backup_metadata_offset + len(metadata)] = metadata

    partition_data = bytearray(block_size)
    partition_data[1024 + 56 : 1024 + 58] = b"\x53\xef"
    partition_data[2000:2012] = b"xos-lavender"
    sparse = sparse_image_bytes(
        block_size,
        [
            (imagectl.CHUNK_RAW, 8, bytes(first_region)),
            (imagectl.CHUNK_DONT_CARE, 248, b""),
            (imagectl.CHUNK_RAW, 1, bytes(partition_data)),
            (imagectl.CHUNK_DONT_CARE, 255, b""),
        ],
    )
    return sparse, bytes(partition_data)


class SparseImageTests(unittest.TestCase):
    def test_reads_raw_fill_and_dont_care_chunks(self) -> None:
        block = 4096
        raw_a = bytes((index % 251 for index in range(block)))
        raw_b = b"B" * block
        expected = raw_a + b"\x12\x34\x56\x78" * (block // 4) + bytes(block) + raw_b
        payload = sparse_image_bytes(
            block,
            [
                (imagectl.CHUNK_RAW, 1, raw_a),
                (imagectl.CHUNK_FILL, 1, b"\x12\x34\x56\x78"),
                (imagectl.CHUNK_DONT_CARE, 1, b""),
                (imagectl.CHUNK_RAW, 1, raw_b),
                (imagectl.CHUNK_CRC32, 0, b"\0\0\0\0"),
            ],
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "fixture.sparse"
            path.write_bytes(payload)
            with imagectl.SparseImage(path) as sparse:
                self.assertEqual(sparse.size, len(expected))
                self.assertEqual(sparse.read_at(block - 7, block * 2 + 14), expected[block - 7 : block * 3 + 7])
                self.assertEqual(sparse.report()["total_chunks"], 5)

    def test_rejects_trailing_sparse_data(self) -> None:
        payload = sparse_image_bytes(
            4096,
            [(imagectl.CHUNK_DONT_CARE, 1, b"")],
        ) + b"trailing"
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "bad.sparse"
            path.write_bytes(payload)
            with self.assertRaises(imagectl.ImageError):
                imagectl.SparseImage(path)


class LogicalPartitionTests(unittest.TestCase):
    def test_parses_and_extracts_partition_from_sparse_super(self) -> None:
        sparse_bytes, expected_partition = synthetic_super_sparse()
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            super_path = root / "super.img"
            super_path.write_bytes(sparse_bytes)
            with imagectl.open_image(super_path) as image:
                metadata = imagectl.read_lp_metadata(image)
                self.assertEqual([partition.name for partition in metadata.partitions], ["system_a"])
                self.assertEqual(imagectl.partition_size(metadata, metadata.partitions[0]), 4096)
                report = imagectl.extract_lp_partitions(
                    image,
                    metadata,
                    ["system_a"],
                    root / "out",
                )
            self.assertEqual((root / "out" / "system_a.img").read_bytes(), expected_partition)
            self.assertEqual(report[0]["filesystem"], "ext4")

    def test_uses_backup_geometry_when_primary_is_corrupt(self) -> None:
        sparse_bytes, _expected_partition = synthetic_super_sparse()
        mutable = bytearray(sparse_bytes)
        sparse_header_size = imagectl.SPARSE_HEADER.size
        chunk_header_size = imagectl.SPARSE_CHUNK_HEADER.size
        raw_payload_start = sparse_header_size + chunk_header_size
        mutable[raw_payload_start + imagectl.LP_RESERVED_BYTES] ^= 0xFF
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "super.img"
            path.write_bytes(mutable)
            with imagectl.open_image(path) as image:
                metadata = imagectl.read_lp_metadata(image)
            self.assertEqual(metadata.geometry.source_copy, "backup")


class TransferListTests(unittest.TestCase):
    def test_converts_full_ota_ranges_to_partition_sized_image(self) -> None:
        block = imagectl.OTA_BLOCK_SIZE
        data = b"A" * block + b"B" * block
        transfer = "\n".join(
            [
                "4",
                "6",
                "0",
                "0",
                "erase 2,0,8",
                "new 4,0,1,4,5",
                "zero 4,1,4,5,6",
                "",
            ]
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            transfer_path = root / "system.transfer.list"
            data_path = root / "system.new.dat"
            output_path = root / "system.img"
            transfer_path.write_text(transfer, encoding="utf-8")
            data_path.write_bytes(data)

            report = imagectl.convert_sdat(transfer_path, data_path, output_path)

            self.assertEqual(output_path.stat().st_size, 8 * block)
            with output_path.open("rb") as output:
                self.assertEqual(output.read(block), b"A" * block)
                output.seek(4 * block)
                self.assertEqual(output.read(block), b"B" * block)
            self.assertEqual(report["new_blocks"], 2)
            self.assertEqual(report["zero_blocks"], 4)

    def test_rejects_overlapping_new_and_zero_ranges(self) -> None:
        transfer = "\n".join(
            [
                "4",
                "3",
                "0",
                "0",
                "new 2,0,2",
                "zero 2,1,2",
            ]
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "bad.transfer.list"
            path.write_text(transfer, encoding="utf-8")
            with self.assertRaises(imagectl.ImageError):
                imagectl.parse_transfer_list(path)


@unittest.skipUnless(find_library("brotlidec"), "libbrotlidec is unavailable")
class BrotliTests(unittest.TestCase):
    def test_decodes_known_brotli_stream(self) -> None:
        expected = b"lavender-xos-brotli-fixture\n" * 100
        encoded = bytes.fromhex(
            "1bef0a004477f877fd7b8fa288885554965c5815aa74b23f470100e27b60ecad"
            "44e4efd1c501"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "fixture.br"
            output = root / "fixture.raw"
            source.write_bytes(encoded)
            size = imagectl.decode_brotli(source, output, len(expected))
            self.assertEqual(size, len(expected))
            self.assertEqual(output.read_bytes(), expected)


if __name__ == "__main__":
    unittest.main()
