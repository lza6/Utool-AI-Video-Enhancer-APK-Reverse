#!/usr/bin/env python3
"""Per-method const-string dump for a class."""
import sys, glob, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dexref import Dex


def strings_per_method(dex, wanted):
    out = []
    nstr = dex.string_ids_size
    for ci, class_idx, cdoff in dex.class_defs():
        if not cdoff:
            continue
        cname = dex.type_name(class_idx)
        if cname not in wanted:
            continue
        try:
            for midx, code_off in dex.methods_of(cdoff):
                s, ln = dex.code_range(code_off)
                chunk = dex.data[s:s + ln]
                lits = []
                for p in range(0, len(chunk) - 2, 2):
                    op = chunk[p - 2] if p >= 2 else -1
                    if op == 0x1a:
                        idx = struct.unpack_from('<H', chunk, p)[0]
                        if idx < nstr:
                            lits.append((p, dex.string_at(idx)))
                    elif op == 0x1b and p + 4 <= len(chunk):
                        idx = struct.unpack_from('<I', chunk, p)[0]
                        if idx < nstr:
                            lits.append((p, dex.string_at(idx)))
                if lits:
                    out.append((cname, dex.method_name(midx)[1], lits))
        except Exception as e:
            pass
    return out


if __name__ == '__main__':
    apkdir = sys.argv[1]
    wanted = set(sys.argv[2:])
    for f in sorted(glob.glob(os.path.join(apkdir, 'classes*.dex'))):
        dex = Dex(f)
        for cname, mname, lits in strings_per_method(dex, wanted):
            print(f'--- {cname}->{mname}')
            seen = set()
            for p, s in lits:
                if s in seen:
                    continue
                seen.add(s)
                if not s.strip():
                    continue
                printable = sum(1 for ch in s if 32 <= ord(ch) < 127) / len(s)
                if printable < 0.9:
                    continue
                print(f'    {s!r}')
