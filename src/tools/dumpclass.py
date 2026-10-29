#!/usr/bin/env python3
"""Dump all const-string literals referenced by the methods of classes matching a name filter."""
import sys, glob, struct, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dexref import Dex


def collect(dex):
    """map class_name -> set of string indices referenced by const-string in its methods"""
    out = {}
    nstr = dex.string_ids_size
    for ci, class_idx, cdoff in dex.class_defs():
        if not cdoff:
            continue
        cname = dex.type_name(class_idx)
        acc = out.setdefault(cname, set())
        try:
            for midx, code_off in dex.methods_of(cdoff):
                s, ln = dex.code_range(code_off)
                chunk = dex.data[s:s + ln]
                for p in range(0, len(chunk) - 2, 2):
                    op = chunk[p - 2] if p >= 2 else -1
                    if op == 0x1a:
                        idx = struct.unpack_from('<H', chunk, p)[0]
                        if idx < nstr:
                            acc.add(idx)
                    elif op == 0x1b and p + 4 <= len(chunk):
                        idx = struct.unpack_from('<I', chunk, p)[0]
                        if idx < nstr:
                            acc.add(idx)
        except Exception:
            pass
    return out


# instruction width in 16-bit code units (DEX format table, subset via formats)
_W = {}


def _width(u):
    op = u & 0xff
    if op == 0x00:
        return 1 if u == 0x0000 else 2 if u == 0x0100 else 1
    if op == 0x02 or op == 0x03 or op == 0x05 or op == 0x06 or op == 0x09 or op == 0x0a:
        return 2   # move/from16, move-wide/from16, move-object/from16, move-result*, move-exception? (0x0d)
    if op == 0x13 or op == 0x15 or op == 0x16 or op == 0x19:
        return 2   # const/16, const/high16, const-wide/16, const-wide/high16
    if op == 0x14:
        return 3   # const
    if op == 0x17:
        return 3   # const-wide/32
    if op == 0x18:
        return 5   # const-wide
    if 0x2d <= op <= 0x3d:
        return 2   # cmp*, if-test*, if-testz*
    if 0x44 <= op <= 0x51:
        return 2   # aget/aput*
    if 0x52 <= op <= 0x5f:
        return 2   # iget/iput*
    if 0x60 <= op <= 0x6d:
        return 2   # sget/sput*
    if 0x6e <= op <= 0x72:
        return 3   # invoke-*
    if op == 0x73:
        return 3   # unused
    if 0x74 <= op <= 0x78:
        return 3   # invoke-*/range
    if 0x90 <= op <= 0xaf:
        return 2   # binop*
    if 0xb0 <= op <= 0xcf:
        return 1   # binop/2addr
    if 0xd0 <= op <= 0xe2:
        return 2   # binop/lit16, lit8
    if 0xfa <= op <= 0xfb:
        return 4   # invoke-polymorphic
    if 0xfc <= op <= 0xfd:
        return 3   # invoke-custom
    if op == 0xfe:
        return 2   # const-method-handle
    if op == 0xff:
        return 2   # const-method-type
    if 0x1c <= op <= 0x1f:
        return 2   # const-class, monitor-*, check-cast, instance-of
    if 0x20 <= op <= 0x22:
        return 2   # array-length, new-instance/array, filled-new-array
    if op == 0x24:
        return 3   # filled-new-array/range
    if op == 0x25:
        return 3   # fill-array-data
    if op == 0x26:
        return 3   # fill-array-data
    if 0x27 <= op <= 0x28:
        return 1   # throw, goto
    if op == 0x29:
        return 1   # goto/16
    if op == 0x2a:
        return 2   # goto/32
    if op == 0x2b <= op <= 0x2c:
        return 3   # packed-switch, sparse-switch
    if 0x2c == op:
        return 3
    if 0x0d == op or 0x07 == op or 0x08 == op or 0x0c == op:
        return 1
    if 0x01 <= op <= 0x09:
        return 1
    if 0x0e <= op <= 0x11:
        return 1
    if op == 0x12:
        return 1
    if 0x32 <= op <= 0x3d:
        return 2
    if op == 0x3e:
        return 1
    return 1


if __name__ == '__main__':
    apkdir = sys.argv[1]
    filt = sys.argv[2] if len(sys.argv) > 2 else ''
    submatch = sys.argv[3] if len(sys.argv) > 3 else ''
    for f in sorted(glob.glob(os.path.join(apkdir, 'classes*.dex'))):
        dex = Dex(f)
        m = collect(dex)
        for cname, idxs in m.items():
            if filt and filt.lower() not in cname.lower():
                continue
            strs = sorted({dex.string_at(i) for i in idxs}, key=len)
            if submatch:
                strs = [s for s in strs if submatch in s]
            if not strs:
                continue
            print('###', cname)
            for s in strs:
                print('   ', s)
