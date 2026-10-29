#!/usr/bin/env python3
"""androguard helper (v4 API): list classes by prefix / dump source / grep string users."""
import sys
import glob
try:
    from loguru import logger as _lg
    _lg.remove()
except Exception:
    pass
from androguard.misc import AnalyzeDex

_CACHE = {}


def load(apkdir='raw'):
    if 'all' in _CACHE:
        return _CACHE['all']
    allpairs = []
    for f in sorted(glob.glob(f'{apkdir}/classes*.dex')):
        d, dx, dxa = AnalyzeDex(f)
        allpairs.append((f, d, dxa))
    _CACHE['all'] = allpairs
    return allpairs


def all_classes():
    for f, d, dxa in load():
        for c in dxa.get_classes():
            yield c


if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'ls':
        pref = sys.argv[2]
        for c in all_classes():
            if c.name.startswith(pref):
                print(c.name)
    elif cmd == 'src':
        want = set(sys.argv[2:])
        for c in all_classes():
            if c.name in want:
                print('// ===== ' + c.name)
                for m in c.get_methods():
                    try:
                        meth = m.get_method()
                        if not hasattr(meth, 'get_source'):
                            continue
                        print(meth.get_source())
                    except Exception as e:
                        print(f'//  [decompile failed {m.name}: {type(e).__name__}]')
    elif cmd == 'xref':
        target_cls, target_m = sys.argv[2], sys.argv[3]
        for c in all_classes():
            for m in c.get_methods():
                if m.name != target_m:
                    continue
                if not c.name.startswith(target_cls):
                    continue
                print(f'== {c.name}->{m.name}{m.descriptor}')
                for xr in m.get_xref_from():
                    try:
                        src_class, src_m = xr[0], xr[1]
                        print(f'   caller: {src_class.name}->{src_m.name}')
                    except Exception:
                        print('   caller: ?', xr)
    elif cmd == 'grep':
        needle = sys.argv[2]
        for c in all_classes():
            for m in c.get_methods():
                try:
                    meth = m.get_method()
                    src = meth.get_source() if hasattr(meth, 'get_source') else None
                except Exception:
                    src = None
                if src and needle in src:
                    print(f'--- {c.name}->{m.name}')
                    print(src)
                    print()
