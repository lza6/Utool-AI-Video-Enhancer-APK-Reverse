#!/usr/bin/env python3
"""Dump all const-strings for every class in a package prefix."""
import sys, glob, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dexref import Dex


def run(apkdir, prefix, filt=None):
    for f in sorted(glob.glob(os.path.join(apkdir, 'classes*.dex'))):
        dex = Dex(f)
        nstr = dex.string_ids_size
        for ci, class_idx, cdoff in dex.class_defs():
            if not cdoff:
                continue
            cname = dex.type_name(class_idx)
            if not cname.startswith(prefix):
                continue
            lits = set()
            try:
                for midx, code_off in dex.methods_of(cdoff):
                    s, ln = dex.code_range(code_off)
                    chunk = dex.data[s:s + ln]
                    for p in range(0, len(chunk) - 2, 2):
                        op = chunk[p - 2] if p >= 2 else -1
                        idx = None
                        if op == 0x1a:
                            idx = struct.unpack_from('<H', chunk, p)[0]
                        elif op == 0x1b and p + 4 <= len(chunk):
                            idx = struct.unpack_from('<I', chunk, p)[0]
                        if idx is not None and idx < nstr:
                            lits.add(dex.string_at(idx))
            except Exception:
                pass
            out = []
            for s in sorted(lits, key=lambda x: (len(x), x)):
                if not s.strip():
                    continue
                if sum(1 for ch in s if 32 <= ord(ch) < 127) / len(s) < 0.95:
                    continue
                if filt and filt not in s:
                    continue
                out.append(s)
            if out:
                print('###', cname)
                for s in out:
                    print('   ', s)


if __name__ == '__main__':
    run(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
