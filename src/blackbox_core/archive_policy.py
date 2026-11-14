"""Bound archive metadata before ZipFile materializes its central directory.

The supported CPython ZIP footer reader handles ZIP64 without loading members.
We then count actual fixed central headers: a forged small footer count must
not turn a bounded member policy into hundreds of thousands of ZipInfo objects.
"""
from contextlib import contextmanager
import os
import struct
import zipfile

MAX_CENTRAL_BYTES = 16 * 1024 * 1024


class _BoundedReads:
    def __init__(self, stream):
        self.stream = stream

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def read(self, size=-1):
        if size is None or size < 0:
            position = self.stream.tell()
            size = self.stream.seek(0, os.SEEK_END) - position
            self.stream.seek(position)
        if size > MAX_CENTRAL_BYTES:
            raise ValueError("ZIP_SINGLE_READ_BUDGET")
        return self.stream.read(size)


def _check_directory(stream, max_members):
    end = zipfile._EndRecData(stream)
    if end is None:
        raise ValueError("ZIP_END_RECORD_MISSING")
    count, size = end[zipfile._ECD_ENTRIES_TOTAL], end[zipfile._ECD_SIZE]
    if (end[zipfile._ECD_DISK_NUMBER] != 0 or end[zipfile._ECD_DISK_START] != 0 or
            end[zipfile._ECD_ENTRIES_THIS_DISK] != count or
            count > max_members or size > MAX_CENTRAL_BYTES):
        raise ValueError("ZIP_DIRECTORY_BUDGET_OR_MULTIDISK")
    stop = end[zipfile._ECD_LOCATION]
    if end[zipfile._ECD_SIGNATURE] == zipfile.stringEndArchive64:
        # CPython3.11.9 reports the ordinary footer location; 3.11.14
        # reports the ZIP64 footer location. Inspect the actual record so
        # the same bounded policy works on both pinned runner interpreters.
        stream.seek(stop)
        signature=stream.read(4)
        if signature==zipfile.stringEndArchive:
            stop -= zipfile.sizeEndCentDir64 + zipfile.sizeEndCentDir64Locator
        elif signature!=zipfile.stringEndArchive64:
            raise ValueError("ZIP_DIRECTORY_FOOTER_LOCATION_INVALID")
    start = stop - size
    if start < 0:
        raise ValueError("ZIP_DIRECTORY_RANGE_INVALID")
    stream.seek(start)
    actual = 0
    while stream.tell() < stop:
        header = stream.read(46)
        if len(header) != 46 or header[:4] != b"PK\x01\x02":
            raise ValueError("ZIP_DIRECTORY_HEADER_INVALID")
        actual += 1
        if actual > max_members:
            raise ValueError("ZIP_MEMBER_BUDGET")
        length = sum(struct.unpack_from("<3H", header, 28))
        if stream.tell() + length > stop:
            raise ValueError("ZIP_DIRECTORY_RANGE_INVALID")
        stream.seek(length, os.SEEK_CUR)
    if actual != count or stream.tell() != stop:
        raise ValueError("ZIP_DIRECTORY_COUNT_MISMATCH")
    return count


@contextmanager
def bounded_zip(path, *, max_members=10000, max_total_bytes):
    if (type(max_members) is not int or not 1 <= max_members <= 10000 or
            type(max_total_bytes) is not int or max_total_bytes < 1):
        raise ValueError("INVALID_ZIP_POLICY")
    try:
        with open(path, "rb") as raw:
            stream = _BoundedReads(raw)
            expected = _check_directory(stream, max_members)
            stream.seek(0)
            with zipfile.ZipFile(stream) as archive:
                members = archive.infolist()
                if len(members) != expected:
                    raise ValueError("ZIP_MEMBER_COUNT_CHANGED")
                if sum(item.file_size for item in members) > max_total_bytes:
                    raise ValueError("ZIP_UNCOMPRESSED_SIZE_BUDGET")
                yield archive
    except (zipfile.BadZipFile, struct.error, OverflowError, EOFError) as error:
        raise ValueError("INVALID_ZIP_STRUCTURE") from error
