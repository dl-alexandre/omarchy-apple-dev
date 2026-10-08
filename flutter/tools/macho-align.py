#!/usr/bin/env python3
"""Re-align a Mach-O string table that an llvm-objcopy based tool left misaligned.

  macho-align.py FILE...

llvm-strip and llvm-install-name-tool re-lay out __LINKEDIT and put the string
pool straight after the indirect symbol table, whose entries are four bytes.
With an odd entry count the pool starts on a 4-byte boundary, and dyld refuses
images built against a recent SDK: "mis-aligned LINKEDIT string pool". Apple's
tools pad it to eight. This inserts that padding in place.

Handles thin 64-bit images and fat files; the string table must be the last
thing in the image and the image unsigned (true of the tools' output on a
linker-fresh file). An image that is already aligned is left as it is.
Exits 1 and leaves the file alone when it cannot fix an image.
"""
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF
LC_SEGMENT_64, LC_SYMTAB, LC_CODE_SIGNATURE = 0x19, 0x2, 0x1D
PAGE = 0x4000


def align_thin(image: bytearray) -> bytearray | None:
    """Returns the fixed image, the same object when nothing is needed, or None."""
    if struct.unpack_from("<I", image, 0)[0] != MH_MAGIC_64:
        return None
    ncmds = struct.unpack_from("<I", image, 16)[0]
    off, symtab, linkedit, signed = 32, None, None, False
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", image, off)
        if cmd == LC_SYMTAB:
            symtab = off
        elif cmd == LC_SEGMENT_64 and image[off + 8:off + 24].rstrip(b"\0") == b"__LINKEDIT":
            linkedit = off
        elif cmd == LC_CODE_SIGNATURE:
            signed = True
        off += size
    if symtab is None or linkedit is None:
        return image
    stroff, strsize = struct.unpack_from("<II", image, symtab + 16)
    pad = -stroff % 8
    if pad == 0 or strsize == 0:
        return image
    if signed or stroff + strsize != len(image):
        return None
    fixed = bytearray(image[:stroff]) + bytes(pad) + image[stroff:]
    struct.pack_into("<I", fixed, symtab + 16, stroff + pad)
    vmsize, _fileoff, filesize = struct.unpack_from("<QQQ", fixed, linkedit + 32)
    filesize += pad
    struct.pack_into("<Q", fixed, linkedit + 48, filesize)
    struct.pack_into("<Q", fixed, linkedit + 32, max(vmsize, -(-filesize // PAGE) * PAGE))
    return fixed


def align_file(path: str) -> bool:
    data = bytearray(open(path, "rb").read())
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        fixed = align_thin(data)
        if fixed is None:
            return False
        if fixed is not data:
            open(path, "wb").write(fixed)
        return True
    wide = magic == FAT_MAGIC_64
    entry, entry_size = (">iiQQII", 32) if wide else (">iiIII", 20)
    count = struct.unpack_from(">I", data, 4)[0]
    slices = [list(struct.unpack_from(entry, data, 8 + i * entry_size)) for i in range(count)]
    out = bytearray(data[:8 + count * entry_size])
    changed = False
    for fields in slices:
        offset, size, align = fields[2], fields[3], fields[4]
        image = bytearray(data[offset:offset + size])
        fixed = align_thin(image)
        if fixed is None:
            return False
        changed |= fixed is not image
        start = -(-len(out) // (1 << align)) * (1 << align)
        out += bytes(start - len(out)) + fixed
        fields[2], fields[3] = start, len(fixed)
    if changed:
        for i, fields in enumerate(slices):
            struct.pack_into(entry, out, 8 + i * entry_size, *fields)
        open(path, "wb").write(out)
    return True


if __name__ == "__main__":
    failed = [p for p in sys.argv[1:] if not align_file(p)]
    for p in failed:
        print(f"macho-align: cannot re-align {p}", file=sys.stderr)
    sys.exit(1 if failed else 0)
