#!/usr/bin/env python3
"""Validated Android OTA, sparse-image, and logical-partition utilities."""

from __future__ import annotations

import argparse
from bisect import bisect_right
import ctypes
from ctypes.util import find_library
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import tempfile
from typing import BinaryIO, Iterator, Protocol


BUFFER_SIZE = 4 * 1024 * 1024
OTA_BLOCK_SIZE = 4096
SECTOR_SIZE = 512

SPARSE_MAGIC = 0xED26FF3A
SPARSE_HEADER = struct.Struct("<IHHHHIIII")
SPARSE_CHUNK_HEADER = struct.Struct("<HHII")
CHUNK_RAW = 0xCAC1
CHUNK_FILL = 0xCAC2
CHUNK_DONT_CARE = 0xCAC3
CHUNK_CRC32 = 0xCAC4

LP_GEOMETRY_MAGIC = 0x616C4467
LP_HEADER_MAGIC = 0x414C5030
LP_MAJOR_VERSION = 10
LP_MAX_MINOR_VERSION = 2
LP_RESERVED_BYTES = 4096
LP_GEOMETRY_SIZE = 4096
LP_GEOMETRY = struct.Struct("<II32sIII")
LP_HEADER_PREFIX = struct.Struct("<IHHI32sI32s")
LP_DESCRIPTOR = struct.Struct("<III")
LP_PARTITION = struct.Struct("<36sIIII")
LP_EXTENT = struct.Struct("<QIQI")
LP_GROUP = struct.Struct("<36sIQ")
LP_BLOCK_DEVICE = struct.Struct("<QIIQ36sI")
LP_TARGET_LINEAR = 0
LP_TARGET_ZERO = 1
LP_ATTR_SLOT_SUFFIXED = 1 << 1
LP_ATTR_DISABLED = 1 << 3
LP_GROUP_SLOT_SUFFIXED = 1 << 0
LP_BLOCK_DEVICE_SLOT_SUFFIXED = 1 << 0

SAFE_NAME = re.compile(r"^[A-Za-z0-9_]+$")


class ImageError(RuntimeError):
    """A malformed or unsupported Android image."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(BUFFER_SIZE), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ImageError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def _read_exact(source: BinaryIO, size: int, label: str) -> bytes:
    data = source.read(size)
    if len(data) != size:
        raise ImageError(f"truncated {label}: expected {size} bytes, got {len(data)}")
    return data


def _read_exact_at(source: BinaryIO, offset: int, size: int, label: str) -> bytes:
    try:
        source.seek(offset)
    except OSError as exc:
        raise ImageError(f"cannot seek to {label}: {exc}") from exc
    return _read_exact(source, size, label)


def _prepare_output(path: Path) -> tuple[BinaryIO, Path]:
    if path.is_symlink():
        raise ImageError(f"refusing symbolic-link output: {path}")
    if path.exists():
        raise ImageError(f"refusing to overwrite existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".partial", dir=path.parent
    )
    return os.fdopen(descriptor, "w+b"), Path(temporary_name)


def _commit_output(output: BinaryIO, temporary: Path, destination: Path) -> None:
    output.flush()
    os.fsync(output.fileno())
    output.close()
    os.replace(temporary, destination)


def _discard_output(output: BinaryIO | None, temporary: Path | None) -> None:
    if output is not None and not output.closed:
        output.close()
    if temporary is not None:
        temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class SparseChunk:
    kind: int
    output_start: int
    output_size: int
    input_offset: int | None = None
    fill: bytes | None = None


class ImageReader(Protocol):
    size: int

    def read_at(self, offset: int, size: int) -> bytes:
        ...

    def copy_range(self, offset: int, size: int, destination: BinaryIO) -> None:
        ...

    def close(self) -> None:
        ...


class RawImage:
    def __init__(self, path: Path):
        if path.is_symlink() or not path.is_file():
            raise ImageError(f"raw image is not a regular file: {path}")
        self.path = path
        self._source = path.open("rb")
        self.size = path.stat().st_size

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise ImageError("raw-image read exceeds image bounds")
        return _read_exact_at(self._source, offset, size, "raw-image range")

    def copy_range(self, offset: int, size: int, destination: BinaryIO) -> None:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise ImageError("raw-image copy exceeds image bounds")
        self._source.seek(offset)
        remaining = size
        while remaining:
            chunk = self._source.read(min(BUFFER_SIZE, remaining))
            if not chunk:
                raise ImageError("raw image ended during range copy")
            destination.write(chunk)
            remaining -= len(chunk)

    def close(self) -> None:
        self._source.close()

    def __enter__(self) -> RawImage:
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


class SparseImage:
    def __init__(self, path: Path):
        if path.is_symlink() or not path.is_file():
            raise ImageError(f"sparse image is not a regular file: {path}")
        self.path = path
        self._source = path.open("rb")
        self.file_size = path.stat().st_size
        self.chunks: list[SparseChunk] = []
        self._starts: list[int] = []
        try:
            self._parse()
        except Exception:
            self._source.close()
            raise

    def _parse(self) -> None:
        raw_header = _read_exact(self._source, SPARSE_HEADER.size, "sparse header")
        (
            magic,
            major,
            minor,
            file_header_size,
            chunk_header_size,
            block_size,
            total_blocks,
            total_chunks,
            image_checksum,
        ) = SPARSE_HEADER.unpack(raw_header)
        if magic != SPARSE_MAGIC:
            raise ImageError("invalid Android sparse-image magic")
        if major != 1:
            raise ImageError(f"unsupported sparse-image major version: {major}")
        if file_header_size < SPARSE_HEADER.size or chunk_header_size < SPARSE_CHUNK_HEADER.size:
            raise ImageError("invalid sparse-image header sizes")
        if block_size == 0 or block_size % 4:
            raise ImageError(f"invalid sparse-image block size: {block_size}")
        if total_blocks == 0 or total_chunks == 0:
            raise ImageError("empty sparse image is unsupported")
        if total_chunks > self.file_size // chunk_header_size:
            raise ImageError("impossible sparse-image chunk count")

        self.major_version = major
        self.minor_version = minor
        self.file_header_size = file_header_size
        self.chunk_header_size = chunk_header_size
        self.block_size = block_size
        self.total_blocks = total_blocks
        self.total_chunks = total_chunks
        self.image_checksum = image_checksum
        self.size = total_blocks * block_size

        self._source.seek(file_header_size)
        output_cursor = 0
        for index in range(total_chunks):
            header = _read_exact(self._source, chunk_header_size, f"sparse chunk {index} header")
            kind, _reserved, chunk_blocks, total_size = SPARSE_CHUNK_HEADER.unpack_from(header)
            if total_size < chunk_header_size:
                raise ImageError(f"invalid total size for sparse chunk {index}")
            payload_size = total_size - chunk_header_size
            output_size = chunk_blocks * block_size
            payload_offset = self._source.tell()
            if payload_offset + payload_size > self.file_size:
                raise ImageError(f"sparse chunk {index} exceeds input file")

            if kind == CHUNK_RAW:
                if output_size == 0 or payload_size != output_size:
                    raise ImageError(f"invalid RAW sparse chunk {index}")
                chunk = SparseChunk(kind, output_cursor, output_size, payload_offset)
                self._source.seek(payload_size, os.SEEK_CUR)
            elif kind == CHUNK_FILL:
                if output_size == 0 or payload_size != 4:
                    raise ImageError(f"invalid FILL sparse chunk {index}")
                fill = _read_exact(self._source, 4, f"sparse chunk {index} fill value")
                chunk = SparseChunk(kind, output_cursor, output_size, fill=fill)
            elif kind == CHUNK_DONT_CARE:
                if output_size == 0 or payload_size != 0:
                    raise ImageError(f"invalid DONT_CARE sparse chunk {index}")
                chunk = SparseChunk(kind, output_cursor, output_size)
            elif kind == CHUNK_CRC32:
                if chunk_blocks != 0 or payload_size != 4:
                    raise ImageError(f"invalid CRC32 sparse chunk {index}")
                _read_exact(self._source, 4, f"sparse chunk {index} CRC32")
                continue
            else:
                raise ImageError(f"unsupported sparse chunk type 0x{kind:04x}")

            self.chunks.append(chunk)
            self._starts.append(output_cursor)
            output_cursor += output_size

        if output_cursor != self.size:
            raise ImageError(
                f"sparse block-count mismatch: expected {self.size}, described {output_cursor}"
            )
        if self._source.tell() != self.file_size:
            raise ImageError("sparse image contains trailing or unparsed bytes")

    def _segments(self, offset: int, size: int) -> Iterator[tuple[SparseChunk, int, int]]:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise ImageError("sparse-image range exceeds expanded image bounds")
        if size == 0:
            return
        index = bisect_right(self._starts, offset) - 1
        if index < 0:
            raise ImageError("sparse-image range is not covered by a chunk")
        cursor = offset
        remaining = size
        while remaining:
            if index >= len(self.chunks):
                raise ImageError("sparse-image range ended outside its chunk map")
            chunk = self.chunks[index]
            chunk_end = chunk.output_start + chunk.output_size
            if cursor < chunk.output_start or cursor >= chunk_end:
                raise ImageError("sparse-image chunk map is not contiguous")
            take = min(remaining, chunk_end - cursor)
            yield chunk, cursor - chunk.output_start, take
            cursor += take
            remaining -= take
            index += 1

    @staticmethod
    def _fill_bytes(pattern: bytes, offset: int, size: int) -> bytes:
        start = offset % len(pattern)
        rotated = pattern[start:] + pattern[:start]
        return (rotated * ((size + 3) // 4))[:size]

    def read_at(self, offset: int, size: int) -> bytes:
        output = bytearray()
        for chunk, relative, take in self._segments(offset, size):
            if chunk.kind == CHUNK_RAW:
                assert chunk.input_offset is not None
                output.extend(
                    _read_exact_at(
                        self._source,
                        chunk.input_offset + relative,
                        take,
                        "sparse RAW range",
                    )
                )
            elif chunk.kind == CHUNK_FILL:
                assert chunk.fill is not None
                output.extend(self._fill_bytes(chunk.fill, relative, take))
            else:
                output.extend(bytes(take))
        return bytes(output)

    def copy_range(self, offset: int, size: int, destination: BinaryIO) -> None:
        for chunk, relative, take in self._segments(offset, size):
            if chunk.kind == CHUNK_DONT_CARE or (
                chunk.kind == CHUNK_FILL and chunk.fill == bytes(4)
            ):
                destination.seek(take, os.SEEK_CUR)
                continue
            copied = 0
            while copied < take:
                amount = min(BUFFER_SIZE, take - copied)
                if chunk.kind == CHUNK_RAW:
                    assert chunk.input_offset is not None
                    data = _read_exact_at(
                        self._source,
                        chunk.input_offset + relative + copied,
                        amount,
                        "sparse RAW range",
                    )
                else:
                    assert chunk.fill is not None
                    data = self._fill_bytes(chunk.fill, relative + copied, amount)
                destination.write(data)
                copied += amount

    def close(self) -> None:
        self._source.close()

    def __enter__(self) -> SparseImage:
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def report(self) -> dict:
        counts: dict[str, int] = {"raw": 0, "fill": 0, "dont_care": 0}
        names = {CHUNK_RAW: "raw", CHUNK_FILL: "fill", CHUNK_DONT_CARE: "dont_care"}
        for chunk in self.chunks:
            counts[names[chunk.kind]] += 1
        return {
            "path": str(self.path),
            "file_size": self.file_size,
            "expanded_size": self.size,
            "major_version": self.major_version,
            "minor_version": self.minor_version,
            "block_size": self.block_size,
            "total_blocks": self.total_blocks,
            "total_chunks": self.total_chunks,
            "image_checksum": f"{self.image_checksum:08x}",
            "mapped_chunk_counts": counts,
        }


def open_image(path: Path) -> RawImage | SparseImage:
    if path.is_symlink() or not path.is_file():
        raise ImageError(f"image is not a regular file: {path}")
    try:
        with path.open("rb") as source:
            magic = _read_exact(source, 4, "image magic")
    except OSError as exc:
        raise ImageError(f"cannot read image {path}: {exc}") from exc
    if struct.unpack("<I", magic)[0] == SPARSE_MAGIC:
        return SparseImage(path)
    return RawImage(path)


@dataclass(frozen=True)
class LpGeometry:
    metadata_max_size: int
    metadata_slot_count: int
    logical_block_size: int
    source_copy: str


@dataclass(frozen=True)
class LpExtent:
    num_sectors: int
    target_type: int
    target_data: int
    target_source: int


@dataclass(frozen=True)
class LpPartition:
    name: str
    attributes: int
    first_extent_index: int
    num_extents: int
    group_index: int


@dataclass(frozen=True)
class LpGroup:
    name: str
    flags: int
    maximum_size: int


@dataclass(frozen=True)
class LpBlockDevice:
    first_logical_sector: int
    alignment: int
    alignment_offset: int
    size: int
    partition_name: str
    flags: int


@dataclass(frozen=True)
class LpMetadata:
    geometry: LpGeometry
    metadata_copy: str
    major_version: int
    minor_version: int
    header_size: int
    tables_size: int
    flags: int
    partitions: tuple[LpPartition, ...]
    extents: tuple[LpExtent, ...]
    groups: tuple[LpGroup, ...]
    block_devices: tuple[LpBlockDevice, ...]


def _decode_lp_name(raw: bytes, label: str) -> str:
    name_raw, separator, padding = raw.partition(b"\0")
    if separator and any(padding):
        raise ImageError(f"{label} contains nonzero bytes after its terminator")
    try:
        name = name_raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ImageError(f"{label} is not ASCII") from exc
    if not SAFE_NAME.fullmatch(name):
        raise ImageError(f"invalid {label}: {name!r}")
    return name


def _parse_geometry_block(block: bytes, copy_name: str) -> LpGeometry:
    magic, struct_size, expected_checksum, max_size, slots, block_size = LP_GEOMETRY.unpack_from(
        block
    )
    if magic != LP_GEOMETRY_MAGIC:
        raise ImageError(f"{copy_name} geometry has invalid magic")
    if struct_size != LP_GEOMETRY.size:
        raise ImageError(f"{copy_name} geometry has invalid structure size")
    checksum_input = bytearray(block[:struct_size])
    checksum_input[8:40] = bytes(32)
    if hashlib.sha256(checksum_input).digest() != expected_checksum:
        raise ImageError(f"{copy_name} geometry checksum mismatch")
    if max_size == 0 or max_size % SECTOR_SIZE:
        raise ImageError(f"{copy_name} geometry has invalid metadata size")
    if slots == 0 or slots > 32:
        raise ImageError(f"{copy_name} geometry has invalid slot count")
    if block_size == 0 or block_size % SECTOR_SIZE:
        raise ImageError(f"{copy_name} geometry has invalid logical block size")
    return LpGeometry(max_size, slots, block_size, copy_name)


def read_lp_geometry(image: ImageReader) -> LpGeometry:
    errors: list[str] = []
    for copy_name, offset in (
        ("primary", LP_RESERVED_BYTES),
        ("backup", LP_RESERVED_BYTES + LP_GEOMETRY_SIZE),
    ):
        try:
            block = image.read_at(offset, LP_GEOMETRY_SIZE)
            return _parse_geometry_block(block, copy_name)
        except ImageError as exc:
            errors.append(str(exc))
    raise ImageError("no valid LP geometry copy: " + "; ".join(errors))


def _descriptor(header: bytes, index: int) -> tuple[int, int, int]:
    return LP_DESCRIPTOR.unpack_from(header, 80 + index * LP_DESCRIPTOR.size)


def _metadata_offset(geometry: LpGeometry, slot: int, backup: bool) -> int:
    base = LP_RESERVED_BYTES + 2 * LP_GEOMETRY_SIZE
    if backup:
        base += geometry.metadata_max_size * geometry.metadata_slot_count
    return base + geometry.metadata_max_size * slot


def _parse_lp_metadata_at(
    image: ImageReader, geometry: LpGeometry, slot: int, backup: bool
) -> LpMetadata:
    copy_name = "backup" if backup else "primary"
    offset = _metadata_offset(geometry, slot, backup)
    prefix = image.read_at(offset, LP_HEADER_PREFIX.size)
    magic, major, minor, header_size, header_checksum, tables_size, tables_checksum = (
        LP_HEADER_PREFIX.unpack(prefix)
    )
    if magic != LP_HEADER_MAGIC:
        raise ImageError(f"{copy_name} metadata has invalid magic")
    if major != LP_MAJOR_VERSION or minor > LP_MAX_MINOR_VERSION:
        raise ImageError(f"{copy_name} metadata has unsupported version {major}.{minor}")
    expected_header_size = 256 if minor >= 2 else 128
    if header_size != expected_header_size:
        raise ImageError(f"{copy_name} metadata has invalid header size")
    if header_size + tables_size > geometry.metadata_max_size:
        raise ImageError(f"{copy_name} metadata exceeds its reserved slot")

    header = image.read_at(offset, header_size)
    header_for_hash = bytearray(header)
    header_for_hash[12:44] = bytes(32)
    if hashlib.sha256(header_for_hash).digest() != header_checksum:
        raise ImageError(f"{copy_name} metadata header checksum mismatch")

    tables = image.read_at(offset + header_size, tables_size)
    if hashlib.sha256(tables).digest() != tables_checksum:
        raise ImageError(f"{copy_name} metadata table checksum mismatch")

    descriptors = [_descriptor(header, index) for index in range(4)]
    expected_entry_sizes = (
        LP_PARTITION.size,
        LP_EXTENT.size,
        LP_GROUP.size,
        LP_BLOCK_DEVICE.size,
    )
    nonempty_ranges: list[tuple[int, int]] = []
    for index, (table_offset, entries, entry_size) in enumerate(descriptors):
        if entry_size != expected_entry_sizes[index]:
            raise ImageError(f"{copy_name} metadata table {index} has invalid entry size")
        table_size = entries * entry_size
        if table_offset > tables_size or table_size > tables_size - table_offset:
            raise ImageError(f"{copy_name} metadata table {index} exceeds table bounds")
        if table_size:
            nonempty_ranges.append((table_offset, table_offset + table_size))
    nonempty_ranges.sort()
    cursor = 0
    for start, end in nonempty_ranges:
        if start != cursor:
            raise ImageError(f"{copy_name} metadata tables overlap or contain gaps")
        cursor = end
    if cursor != tables_size:
        raise ImageError(f"{copy_name} metadata tables do not consume tables_size")

    def entries_for(index: int) -> Iterator[bytes]:
        table_offset, count, entry_size = descriptors[index]
        for entry_index in range(count):
            start = table_offset + entry_index * entry_size
            yield tables[start : start + entry_size]

    groups: list[LpGroup] = []
    for entry in entries_for(2):
        raw_name, flags, maximum_size = LP_GROUP.unpack(entry)
        name = _decode_lp_name(raw_name, "LP group name")
        if flags & ~LP_GROUP_SLOT_SUFFIXED:
            raise ImageError(f"LP group {name} has unsupported flags")
        if flags & LP_GROUP_SLOT_SUFFIXED:
            name += f"_{chr(ord('a') + slot)}"
        groups.append(LpGroup(name, flags, maximum_size))
    if not groups:
        raise ImageError("LP metadata contains no partition groups")

    devices: list[LpBlockDevice] = []
    for entry in entries_for(3):
        first_sector, alignment, alignment_offset, size, raw_name, flags = LP_BLOCK_DEVICE.unpack(
            entry
        )
        name = _decode_lp_name(raw_name, "LP block-device name")
        if flags & ~LP_BLOCK_DEVICE_SLOT_SUFFIXED:
            raise ImageError(f"LP block device {name} has unsupported flags")
        if flags & LP_BLOCK_DEVICE_SLOT_SUFFIXED:
            name += f"_{chr(ord('a') + slot)}"
        if size == 0 or size % SECTOR_SIZE:
            raise ImageError(f"LP block device {name} has invalid size")
        devices.append(LpBlockDevice(first_sector, alignment, alignment_offset, size, name, flags))
    if not devices:
        raise ImageError("LP metadata contains no block devices")
    if devices[0].size > image.size:
        raise ImageError("LP super block-device size exceeds the supplied image")
    metadata_region = (
        LP_RESERVED_BYTES
        + 2 * LP_GEOMETRY_SIZE
        + 2 * geometry.metadata_max_size * geometry.metadata_slot_count
    )
    if metadata_region > devices[0].first_logical_sector * SECTOR_SIZE:
        raise ImageError("LP metadata overlaps logical partition contents")

    extents: list[LpExtent] = []
    for entry in entries_for(1):
        num_sectors, target_type, target_data, target_source = LP_EXTENT.unpack(entry)
        if num_sectors == 0:
            raise ImageError("LP metadata contains an empty extent")
        if target_type not in (LP_TARGET_LINEAR, LP_TARGET_ZERO):
            raise ImageError(f"unsupported LP extent target type: {target_type}")
        if target_type == LP_TARGET_LINEAR:
            if target_source >= len(devices):
                raise ImageError("LP extent references an invalid block device")
            device = devices[target_source]
            if target_data + num_sectors > device.size // SECTOR_SIZE:
                raise ImageError("LP extent exceeds its block device")
        elif target_data != 0 or target_source != 0:
            raise ImageError("LP zero extent has nonzero target fields")
        extents.append(LpExtent(num_sectors, target_type, target_data, target_source))

    partitions: list[LpPartition] = []
    seen_names: set[str] = set()
    valid_attributes = 0x3 if minor == 0 else 0xF
    for entry in entries_for(0):
        raw_name, attributes, first_extent, extent_count, group_index = LP_PARTITION.unpack(entry)
        name = _decode_lp_name(raw_name, "LP partition name")
        if attributes & ~valid_attributes:
            raise ImageError(f"LP partition {name} has unsupported attributes")
        if first_extent + extent_count > len(extents):
            raise ImageError(f"LP partition {name} has an invalid extent list")
        if group_index >= len(groups):
            raise ImageError(f"LP partition {name} has an invalid group index")
        if attributes & LP_ATTR_SLOT_SUFFIXED:
            name += f"_{chr(ord('a') + slot)}"
        if name in seen_names:
            raise ImageError(f"duplicate LP partition name: {name}")
        seen_names.add(name)
        partitions.append(LpPartition(name, attributes, first_extent, extent_count, group_index))

    flags = struct.unpack_from("<I", header, 128)[0] if header_size >= 256 else 0
    return LpMetadata(
        geometry=geometry,
        metadata_copy=copy_name,
        major_version=major,
        minor_version=minor,
        header_size=header_size,
        tables_size=tables_size,
        flags=flags,
        partitions=tuple(partitions),
        extents=tuple(extents),
        groups=tuple(groups),
        block_devices=tuple(devices),
    )


def read_lp_metadata(image: ImageReader, slot: int = 0) -> LpMetadata:
    geometry = read_lp_geometry(image)
    if slot < 0 or slot >= geometry.metadata_slot_count:
        raise ImageError(f"LP metadata slot {slot} is out of range")
    errors: list[str] = []
    for backup in (False, True):
        try:
            return _parse_lp_metadata_at(image, geometry, slot, backup)
        except ImageError as exc:
            errors.append(str(exc))
    raise ImageError("no valid LP metadata copy: " + "; ".join(errors))


def partition_size(metadata: LpMetadata, partition: LpPartition) -> int:
    selected = metadata.extents[
        partition.first_extent_index : partition.first_extent_index + partition.num_extents
    ]
    return sum(extent.num_sectors * SECTOR_SIZE for extent in selected)


def lp_report(metadata: LpMetadata) -> dict:
    return {
        "geometry": asdict(metadata.geometry),
        "metadata": {
            "copy": metadata.metadata_copy,
            "version": f"{metadata.major_version}.{metadata.minor_version}",
            "header_size": metadata.header_size,
            "tables_size": metadata.tables_size,
            "flags": metadata.flags,
        },
        "block_devices": [asdict(device) for device in metadata.block_devices],
        "groups": [asdict(group) for group in metadata.groups],
        "partitions": [
            {
                **asdict(partition),
                "group": metadata.groups[partition.group_index].name,
                "size": partition_size(metadata, partition),
            }
            for partition in metadata.partitions
        ],
    }


def _filesystem_type(path: Path) -> str:
    try:
        with path.open("rb") as source:
            source.seek(1024 + 56)
            magic = source.read(2)
    except OSError as exc:
        raise ImageError(f"cannot probe filesystem in {path}: {exc}") from exc
    return "ext4" if magic == b"\x53\xef" else "unknown"


def extract_lp_partitions(
    image: ImageReader,
    metadata: LpMetadata,
    names: list[str],
    output_dir: Path,
) -> list[dict]:
    if len(names) != len(set(names)):
        raise ImageError("duplicate partition requested for extraction")
    by_name = {partition.name: partition for partition in metadata.partitions}
    missing = [name for name in names if name not in by_name]
    if missing:
        raise ImageError("LP partitions not found: " + ", ".join(missing))

    output_dir.mkdir(parents=True, exist_ok=True)
    reports: list[dict] = []
    for name in names:
        partition = by_name[name]
        if partition.attributes & LP_ATTR_DISABLED:
            raise ImageError(f"refusing to extract disabled LP partition: {name}")
        destination = output_dir / f"{name}.img"
        output: BinaryIO | None = None
        temporary: Path | None = None
        expected_size = partition_size(metadata, partition)
        try:
            output, temporary = _prepare_output(destination)
            extents = metadata.extents[
                partition.first_extent_index : partition.first_extent_index + partition.num_extents
            ]
            for extent in extents:
                extent_size = extent.num_sectors * SECTOR_SIZE
                if extent.target_type == LP_TARGET_ZERO:
                    output.seek(extent_size, os.SEEK_CUR)
                    continue
                if extent.target_source != 0:
                    raise ImageError(
                        f"partition {name} needs external block device index {extent.target_source}"
                    )
                image.copy_range(extent.target_data * SECTOR_SIZE, extent_size, output)
            output.truncate(expected_size)
            if output.tell() != expected_size:
                raise ImageError(f"partition {name} extraction length mismatch")
            _commit_output(output, temporary, destination)
            output = None
            temporary = None
        except Exception:
            _discard_output(output, temporary)
            raise

        actual_size = destination.stat().st_size
        if actual_size != expected_size:
            raise ImageError(f"partition {name} output size mismatch")
        reports.append(
            {
                "partition": name,
                "path": str(destination),
                "size": actual_size,
                "allocated_bytes": destination.stat().st_blocks * 512,
                "sha256": sha256_file(destination),
                "filesystem": _filesystem_type(destination),
            }
        )
    return reports


@dataclass(frozen=True)
class TransferCommand:
    operation: str
    ranges: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class TransferPlan:
    version: int
    declared_blocks: int
    commands: tuple[TransferCommand, ...]
    new_blocks: int
    zero_blocks: int
    image_blocks: int


def _parse_ranges(encoded: str, line_number: int) -> tuple[tuple[int, int], ...]:
    try:
        values = [int(value) for value in encoded.split(",")]
    except ValueError as exc:
        raise ImageError(f"invalid block range on transfer-list line {line_number}") from exc
    if not values or values[0] <= 0 or values[0] % 2 or len(values) != values[0] + 1:
        raise ImageError(f"invalid range-set shape on transfer-list line {line_number}")
    ranges: list[tuple[int, int]] = []
    previous_end = -1
    for index in range(1, len(values), 2):
        start, end = values[index], values[index + 1]
        if start < 0 or end <= start or start < previous_end:
            raise ImageError(f"invalid ordered range on transfer-list line {line_number}")
        ranges.append((start, end))
        previous_end = end
    return tuple(ranges)


def parse_transfer_list(path: Path) -> TransferPlan:
    if path.is_symlink() or not path.is_file():
        raise ImageError(f"transfer list is not a regular file: {path}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ImageError(f"cannot read transfer list {path}: {exc}") from exc
    if len(lines) < 2:
        raise ImageError("transfer list is truncated")
    try:
        version = int(lines[0])
        declared_blocks = int(lines[1])
    except ValueError as exc:
        raise ImageError("transfer-list header is not numeric") from exc
    if version not in (1, 2, 3, 4) or declared_blocks <= 0:
        raise ImageError("unsupported transfer-list header")
    command_start = 4 if version >= 2 else 2
    if len(lines) < command_start:
        raise ImageError("transfer-list header is truncated")

    commands: list[TransferCommand] = []
    final_ranges: list[tuple[int, int, str]] = []
    new_blocks = 0
    zero_blocks = 0
    image_blocks = 0
    for line_number, raw_line in enumerate(lines[command_start:], start=command_start + 1):
        if not raw_line.strip():
            continue
        fields = raw_line.split(maxsplit=1)
        if len(fields) != 2 or fields[0] not in {"new", "zero", "erase"}:
            operation = fields[0] if fields else "<empty>"
            raise ImageError(f"unsupported transfer operation {operation!r} on line {line_number}")
        operation, encoded = fields
        ranges = _parse_ranges(encoded, line_number)
        commands.append(TransferCommand(operation, ranges))
        blocks = sum(end - start for start, end in ranges)
        if operation == "new":
            new_blocks += blocks
            final_ranges.extend((start, end, operation) for start, end in ranges)
        elif operation == "zero":
            zero_blocks += blocks
            final_ranges.extend((start, end, operation) for start, end in ranges)
        image_blocks = max(image_blocks, max(end for _start, end in ranges))

    if not commands or new_blocks == 0 or image_blocks == 0:
        raise ImageError("transfer list does not describe a full image")
    if new_blocks + zero_blocks != declared_blocks:
        raise ImageError(
            "transfer-list block count differs from the combined new and zero ranges"
        )
    final_ranges.sort()
    previous_end = -1
    for start, end, operation in final_ranges:
        if start < previous_end:
            raise ImageError(f"overlapping final transfer range at {operation} {start},{end}")
        previous_end = end
    return TransferPlan(
        version,
        declared_blocks,
        tuple(commands),
        new_blocks,
        zero_blocks,
        image_blocks,
    )


def convert_sdat(transfer_path: Path, data_path: Path, output_path: Path) -> dict:
    plan = parse_transfer_list(transfer_path)
    expected_data_size = plan.new_blocks * OTA_BLOCK_SIZE
    if data_path.is_symlink() or not data_path.is_file():
        raise ImageError(f"new.dat is not a regular file: {data_path}")
    if data_path.stat().st_size != expected_data_size:
        raise ImageError(
            f"new.dat size mismatch: expected {expected_data_size}, got {data_path.stat().st_size}"
        )

    output: BinaryIO | None = None
    temporary: Path | None = None
    try:
        output, temporary = _prepare_output(output_path)
        output.truncate(plan.image_blocks * OTA_BLOCK_SIZE)
        with data_path.open("rb") as data:
            for command in plan.commands:
                if command.operation != "new":
                    continue
                for start, end in command.ranges:
                    output.seek(start * OTA_BLOCK_SIZE)
                    remaining = (end - start) * OTA_BLOCK_SIZE
                    while remaining:
                        chunk = data.read(min(BUFFER_SIZE, remaining))
                        if not chunk:
                            raise ImageError("new.dat ended during block transfer")
                        output.write(chunk)
                        remaining -= len(chunk)
            if data.read(1):
                raise ImageError("new.dat has trailing data")
        _commit_output(output, temporary, output_path)
        output = None
        temporary = None
    except Exception:
        _discard_output(output, temporary)
        raise

    return {
        "path": str(output_path),
        "size": output_path.stat().st_size,
        "allocated_bytes": output_path.stat().st_blocks * 512,
        "sha256": sha256_file(output_path),
        "filesystem": _filesystem_type(output_path),
        "transfer_version": plan.version,
        "new_blocks": plan.new_blocks,
        "zero_blocks": plan.zero_blocks,
        "image_blocks": plan.image_blocks,
    }


def _brotli_library() -> ctypes.CDLL:
    library_name = find_library("brotlidec")
    if not library_name:
        raise ImageError("libbrotlidec is required but was not found")
    library = ctypes.CDLL(library_name)
    byte_pointer = ctypes.POINTER(ctypes.c_uint8)
    library.BrotliDecoderCreateInstance.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    library.BrotliDecoderCreateInstance.restype = ctypes.c_void_p
    library.BrotliDecoderDestroyInstance.argtypes = [ctypes.c_void_p]
    library.BrotliDecoderDestroyInstance.restype = None
    library.BrotliDecoderDecompressStream.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(byte_pointer),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(byte_pointer),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    library.BrotliDecoderDecompressStream.restype = ctypes.c_int
    library.BrotliDecoderGetErrorCode.argtypes = [ctypes.c_void_p]
    library.BrotliDecoderGetErrorCode.restype = ctypes.c_int
    library.BrotliDecoderErrorString.argtypes = [ctypes.c_int]
    library.BrotliDecoderErrorString.restype = ctypes.c_char_p
    return library


def decode_brotli(source_path: Path, output_path: Path, expected_size: int | None = None) -> int:
    if source_path.is_symlink() or not source_path.is_file():
        raise ImageError(f"Brotli input is not a regular file: {source_path}")
    library = _brotli_library()
    state = library.BrotliDecoderCreateInstance(None, None, None)
    if not state:
        raise ImageError("could not create Brotli decoder")

    output: BinaryIO | None = None
    temporary: Path | None = None
    total_output = 0
    try:
        output, temporary = _prepare_output(output_path)
        with source_path.open("rb") as source:
            input_bytes = b""
            input_buffer = None
            available_input = ctypes.c_size_t(0)
            next_input = ctypes.POINTER(ctypes.c_uint8)()
            eof = False
            while True:
                if available_input.value == 0 and not eof:
                    input_bytes = source.read(BUFFER_SIZE)
                    if input_bytes:
                        input_buffer = (ctypes.c_uint8 * len(input_bytes)).from_buffer_copy(input_bytes)
                        available_input = ctypes.c_size_t(len(input_bytes))
                        next_input = ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_uint8))
                    else:
                        eof = True

                output_buffer = (ctypes.c_uint8 * BUFFER_SIZE)()
                available_output = ctypes.c_size_t(BUFFER_SIZE)
                next_output = ctypes.cast(output_buffer, ctypes.POINTER(ctypes.c_uint8))
                result = library.BrotliDecoderDecompressStream(
                    state,
                    ctypes.byref(available_input),
                    ctypes.byref(next_input),
                    ctypes.byref(available_output),
                    ctypes.byref(next_output),
                    None,
                )
                produced = BUFFER_SIZE - available_output.value
                if produced:
                    output.write(ctypes.string_at(output_buffer, produced))
                    total_output += produced
                    if expected_size is not None and total_output > expected_size:
                        raise ImageError("Brotli output exceeds its expected size")

                if result == 1:  # BROTLI_DECODER_RESULT_SUCCESS
                    if available_input.value != 0 or source.read(1):
                        raise ImageError("Brotli stream contains trailing data")
                    break
                if result == 2:  # BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT
                    if available_input.value != 0:
                        raise ImageError("Brotli decoder stalled with unconsumed input")
                    if eof:
                        raise ImageError("Brotli stream is truncated")
                    continue
                if result == 3:  # BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT
                    if produced == 0:
                        raise ImageError("Brotli decoder requested output without progress")
                    continue

                error_code = library.BrotliDecoderGetErrorCode(state)
                error_text = library.BrotliDecoderErrorString(error_code)
                message = error_text.decode("utf-8", errors="replace") if error_text else str(error_code)
                raise ImageError(f"Brotli decoder failed: {message}")

        if expected_size is not None and total_output != expected_size:
            raise ImageError(
                f"Brotli output size mismatch: expected {expected_size}, got {total_output}"
            )
        _commit_output(output, temporary, output_path)
        output = None
        temporary = None
    except Exception:
        _discard_output(output, temporary)
        raise
    finally:
        library.BrotliDecoderDestroyInstance(state)
    return total_output


def convert_ota_image(transfer_path: Path, brotli_path: Path, output_path: Path) -> dict:
    plan = parse_transfer_list(transfer_path)
    expected_data_size = plan.new_blocks * OTA_BLOCK_SIZE
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".ota-data-", dir=output_path.parent) as temporary_dir:
        data_path = Path(temporary_dir) / "new.dat"
        decode_brotli(brotli_path, data_path, expected_data_size)
        report = convert_sdat(transfer_path, data_path, output_path)
    report["brotli_path"] = str(brotli_path)
    report["brotli_size"] = brotli_path.stat().st_size
    report["new_data_size"] = expected_data_size
    return report


def command_sparse_info(args: argparse.Namespace) -> None:
    with SparseImage(args.image) as image:
        print(json.dumps(image.report(), indent=2, sort_keys=True))


def command_lp_info(args: argparse.Namespace) -> None:
    with open_image(args.image) as image:
        metadata = read_lp_metadata(image, args.slot)
        report = lp_report(metadata)
        if isinstance(image, SparseImage):
            report["sparse"] = image.report()
        else:
            report["raw_image_size"] = image.size
        print(json.dumps(report, indent=2, sort_keys=True))


def command_lp_extract(args: argparse.Namespace) -> None:
    with open_image(args.image) as image:
        metadata = read_lp_metadata(image, args.slot)
        reports = extract_lp_partitions(image, metadata, args.partition, args.output_dir)
    print(json.dumps({"partitions": reports}, indent=2, sort_keys=True))


def command_sdat2img(args: argparse.Namespace) -> None:
    print(json.dumps(convert_sdat(args.transfer_list, args.data, args.output), indent=2, sort_keys=True))


def command_ota_image(args: argparse.Namespace) -> None:
    print(
        json.dumps(
            convert_ota_image(args.transfer_list, args.brotli_data, args.output),
            indent=2,
            sort_keys=True,
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    sparse_parser = subparsers.add_parser("sparse-info", help="validate an Android sparse image")
    sparse_parser.add_argument("image", type=Path)
    sparse_parser.set_defaults(handler=command_sparse_info)

    lp_info_parser = subparsers.add_parser("lp-info", help="validate and describe LP metadata")
    lp_info_parser.add_argument("image", type=Path)
    lp_info_parser.add_argument("--slot", type=int, default=0)
    lp_info_parser.set_defaults(handler=command_lp_info)

    lp_extract_parser = subparsers.add_parser(
        "lp-extract", help="extract named logical partitions from super.img"
    )
    lp_extract_parser.add_argument("image", type=Path)
    lp_extract_parser.add_argument("--slot", type=int, default=0)
    lp_extract_parser.add_argument("--partition", action="append", required=True)
    lp_extract_parser.add_argument("--output-dir", type=Path, required=True)
    lp_extract_parser.set_defaults(handler=command_lp_extract)

    sdat_parser = subparsers.add_parser("sdat2img", help="apply a full-OTA transfer list")
    sdat_parser.add_argument("--transfer-list", type=Path, required=True)
    sdat_parser.add_argument("--data", type=Path, required=True)
    sdat_parser.add_argument("--output", type=Path, required=True)
    sdat_parser.set_defaults(handler=command_sdat2img)

    ota_parser = subparsers.add_parser(
        "ota-image", help="decode a Brotli full-OTA payload and build its raw image"
    )
    ota_parser.add_argument("--transfer-list", type=Path, required=True)
    ota_parser.add_argument("--brotli-data", type=Path, required=True)
    ota_parser.add_argument("--output", type=Path, required=True)
    ota_parser.set_defaults(handler=command_ota_image)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.handler(args)
    except ImageError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
