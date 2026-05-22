"""Raw disk sector reader for Windows.

Reads raw bytes directly from physical drives or logical partitions,
bypassing the filesystem. This allows finding data from deleted files
that haven't been overwritten yet.

REQUIRES: Run as Administrator on Windows.

How it works:
- Opens \\.\PhysicalDriveN or \\.\X: (logical drive letter)
- Reads sector by sector (512 bytes or 4096 bytes)
- Passes raw data to the carver module for pattern matching

All operations are READ-ONLY. Nothing is written to disk.
"""

from __future__ import annotations

import ctypes
import logging
import os
import platform
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Generator, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Sector size (standard)
SECTOR_SIZE = 512
# Read in chunks for performance (1 MB at a time = 2048 sectors)
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MB
# Large chunk for faster scanning (4 MB)
FAST_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB


@dataclass
class DiskInfo:
    """Information about a disk/partition."""
    path: str           # e.g., "\\\\.\\PhysicalDrive0" or "\\\\.\\D:"
    size_bytes: int     # Total size in bytes
    size_gb: float      # Size in GB
    label: str          # Human-readable label
    disk_type: str      # "physical" or "logical"


def is_admin() -> bool:
    """Check if running with Administrator privileges (Windows)."""
    if platform.system() != "Windows":
        return os.geteuid() == 0  # Linux/macOS root check
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, OSError):
        return False


def list_available_drives() -> List[DiskInfo]:
    """List available drives on the system.

    Returns both physical drives and logical partitions.
    """
    drives: List[DiskInfo] = []
    system = platform.system()

    if system == "Windows":
        # List logical drives (D:, E:, F:, etc.)
        import string
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i, letter in enumerate(string.ascii_uppercase):
            if bitmask & (1 << i):
                drive_path = f"\\\\.\\{letter}:"
                drive_label = f"{letter}:\\"
                # Try to get drive size
                size = _get_drive_size_windows(drive_path)
                if size and size > 0:
                    drives.append(DiskInfo(
                        path=drive_path,
                        size_bytes=size,
                        size_gb=size / (1024**3),
                        label=drive_label,
                        disk_type="logical",
                    ))

        # List physical drives (try 0-9)
        for i in range(10):
            drive_path = f"\\\\.\\PhysicalDrive{i}"
            size = _get_drive_size_windows(drive_path)
            if size and size > 0:
                drives.append(DiskInfo(
                    path=drive_path,
                    size_bytes=size,
                    size_gb=size / (1024**3),
                    label=f"Physical Drive {i}",
                    disk_type="physical",
                ))

    elif system == "Linux":
        # List block devices
        import glob
        for dev in sorted(glob.glob("/dev/sd[a-z]") + glob.glob("/dev/nvme[0-9]n[0-9]")):
            size_path = f"/sys/block/{os.path.basename(dev)}/size"
            if os.path.exists(size_path):
                with open(size_path) as f:
                    sectors = int(f.read().strip())
                size = sectors * SECTOR_SIZE
                drives.append(DiskInfo(
                    path=dev,
                    size_bytes=size,
                    size_gb=size / (1024**3),
                    label=os.path.basename(dev),
                    disk_type="physical",
                ))
        # Partitions
        for dev in sorted(glob.glob("/dev/sd[a-z][0-9]*") + glob.glob("/dev/nvme*p[0-9]*")):
            try:
                size = os.path.getsize(dev) if os.path.exists(dev) else 0
            except OSError:
                size = 0
            if size > 0:
                drives.append(DiskInfo(
                    path=dev,
                    size_bytes=size,
                    size_gb=size / (1024**3),
                    label=os.path.basename(dev),
                    disk_type="logical",
                ))

    return drives


def _get_drive_size_windows(path: str) -> Optional[int]:
    """Get drive size on Windows using DeviceIoControl or GetDiskFreeSpaceEx."""
    try:
        # Try opening the drive
        import ctypes.wintypes

        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C

        handle = ctypes.windll.kernel32.CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )

        if handle == -1 or handle == 0xFFFFFFFFFFFFFFFF:
            # Fallback: try GetDiskFreeSpaceEx for logical drives
            if len(path) == 6 and path[4].isalpha():  # \\.\\X:
                letter = path[4] + ":\\"
                free = ctypes.c_ulonglong(0)
                total = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    letter, None, ctypes.byref(total), ctypes.byref(free)
                )
                return total.value if total.value > 0 else None
            return None

        # IOCTL_DISK_GET_LENGTH_INFO
        length = ctypes.c_longlong(0)
        bytes_returned = ctypes.c_ulong(0)

        result = ctypes.windll.kernel32.DeviceIoControl(
            handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            None, 0,
            ctypes.byref(length), ctypes.sizeof(length),
            ctypes.byref(bytes_returned),
            None,
        )

        ctypes.windll.kernel32.CloseHandle(handle)

        if result:
            return length.value

        return None
    except Exception:
        return None


class RawDiskReader:
    """Reads raw sectors from a disk or partition.

    Usage:
        reader = RawDiskReader("\\\\.\\D:")
        for offset, chunk in reader.read_chunks():
            # process raw bytes
            pass
    """

    def __init__(
        self,
        disk_path: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        start_offset: int = 0,
        end_offset: Optional[int] = None,
    ):
        """
        Args:
            disk_path: Path to disk (e.g., "\\\\.\\D:" or "\\\\.\\PhysicalDrive1")
            chunk_size: Bytes to read per iteration (must be multiple of 512)
            start_offset: Byte offset to start reading from
            end_offset: Byte offset to stop reading (None = entire disk)
        """
        self.disk_path = disk_path
        self.chunk_size = chunk_size - (chunk_size % SECTOR_SIZE)  # Align to sector
        if self.chunk_size == 0:
            self.chunk_size = SECTOR_SIZE
        self.start_offset = start_offset - (start_offset % SECTOR_SIZE)
        self.end_offset = end_offset
        self._handle = None
        self._file = None

    def open(self) -> bool:
        """Open the disk for reading. Returns True on success."""
        system = platform.system()

        if system == "Windows":
            return self._open_windows()
        else:
            return self._open_unix()

    def _open_windows(self) -> bool:
        """Open disk on Windows using CreateFileW."""
        try:
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3
            FILE_FLAG_NO_BUFFERING = 0x20000000

            handle = ctypes.windll.kernel32.CreateFileW(
                self.disk_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_NO_BUFFERING,
                None,
            )

            invalid_handle = -1 if sys.maxsize > 2**32 else 0xFFFFFFFF
            if handle == invalid_handle:
                error = ctypes.windll.kernel32.GetLastError()
                logger.error(f"Cannot open {self.disk_path}: Windows error {error}")
                if error == 5:
                    logger.error("Access denied — run as Administrator!")
                return False

            self._handle = handle
            return True

        except Exception as e:
            logger.error(f"Failed to open {self.disk_path}: {e}")
            return False

    def _open_unix(self) -> bool:
        """Open disk on Linux/macOS."""
        try:
            self._file = open(self.disk_path, "rb")
            return True
        except PermissionError:
            logger.error(f"Permission denied: {self.disk_path} — run as root (sudo)")
            return False
        except OSError as e:
            logger.error(f"Cannot open {self.disk_path}: {e}")
            return False

    def close(self):
        """Close the disk handle."""
        if self._handle is not None:
            ctypes.windll.kernel32.CloseHandle(self._handle)
            self._handle = None
        if self._file is not None:
            self._file.close()
            self._file = None

    def read_chunks(
        self,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Generator[Tuple[int, bytes], None, None]:
        """Generator that yields (offset, chunk_bytes) tuples.

        Args:
            progress_callback: Called with (bytes_read, total_bytes) periodically.

        Yields:
            Tuples of (byte_offset, raw_bytes).
        """
        if self._handle is None and self._file is None:
            if not self.open():
                return

        offset = self.start_offset
        total_read = 0
        errors = 0
        max_errors = 1000  # Stop if too many consecutive read errors

        # Seek to start
        if platform.system() == "Windows":
            self._seek_windows(offset)
        else:
            self._file.seek(offset)

        while True:
            # Check end condition
            if self.end_offset and offset >= self.end_offset:
                break

            # Read chunk
            try:
                if platform.system() == "Windows":
                    data = self._read_windows(self.chunk_size)
                else:
                    data = self._file.read(self.chunk_size)

                if not data:
                    break  # End of disk

                yield (offset, data)

                offset += len(data)
                total_read += len(data)
                errors = 0  # Reset error counter on success

                # Progress callback every 100 MB
                if progress_callback and total_read % (100 * 1024 * 1024) < self.chunk_size:
                    progress_callback(total_read, self.end_offset or 0)

            except Exception as e:
                errors += 1
                if errors > max_errors:
                    logger.warning(f"Too many read errors at offset {offset}, stopping.")
                    break
                # Skip this chunk
                offset += self.chunk_size
                if platform.system() == "Windows":
                    self._seek_windows(offset)
                else:
                    try:
                        self._file.seek(offset)
                    except OSError:
                        break
                continue

    def _seek_windows(self, offset: int):
        """Seek to offset on Windows disk handle."""
        high = ctypes.c_long((offset >> 32) & 0xFFFFFFFF)
        low = offset & 0xFFFFFFFF
        ctypes.windll.kernel32.SetFilePointer(
            self._handle, low, ctypes.byref(high), 0  # FILE_BEGIN
        )

    def _read_windows(self, size: int) -> bytes:
        """Read bytes from Windows disk handle."""
        buf = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_ulong(0)
        result = ctypes.windll.kernel32.ReadFile(
            self._handle,
            buf,
            size,
            ctypes.byref(bytes_read),
            None,
        )
        if not result or bytes_read.value == 0:
            return b""
        return buf.raw[:bytes_read.value]

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    def __del__(self):
        self.close()
