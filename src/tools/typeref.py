#!/usr/bin/env python3
"""Find classes/methods referencing a given TYPE descriptor (const-class / new-instance / invoke / check-cast ...)."""
import sys, glob, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dexref import Dex

TYPE_OPS = {0x1c, 0x1f, 0x20, 0x22, 0x23, 0x24, 0x25,
            0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78,
            0xfa, 0xfb, 0xfc, 0xfd}


def find(dex, type_desc):
    tidx = None
    for i in range(dex.type_ids_size):
        if dex.type_name(i) == type_desc:
            tidx = i
            break
    if tidx is None:
        return []
    pat = struct.pack('<H', tidx)
    hits = []
    for ci, class_idx, cdoff in dex.class_defs():
        if not cdoff:
            continue
        cname = dex.type_name(class_idx)
        try:
            for midx, code_off in dex.methods_of(cdoff):
                s, ln = dex.code_range(code_off)
                chunk = dex.data[s:s + ln]
                p = 0
                while True:
                    p = chunk.find(pat, p)
                    if p < 0:
                        break
                    if p % 2 == 0 and p >= 2 and chunk[p - 2] in TYPE_OPS:
                        hits.append((cname, dex.method_name(midx)[1], chunk[p - 2]))
                        break
                    p += 1
        except Exception:
            pass
    return hits


if __name__ == '__main__':
    apkdir = sys.argv[1]
    for target in sys.argv[2:]:
        print('===', target)
        seen = set()
        for f in sorted(glob.glob(os.path.join(apkdir, 'classes*.dex'))):
            dex = Dex(f)
            for cname, mname, op in find(dex, target):
                key = (cname, mname)
                if key in seen:
                    continue
                seen.add(key)
                print(f'    {cname}->{mname} (op={op:#x})')
