#!/usr/bin/env python3
"""Minimal DEX reader: locate which class/method references given strings."""
import struct, sys, glob, os, json

class Dex:
    def __init__(self, path):
        self.data = open(path, 'rb').read()
        d = self.data
        (self.string_ids_size, self.string_ids_off,
         self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off,
         self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off,
         self.class_defs_size, self.class_defs_off) = struct.unpack_from('<12I', d, 0x38)
        self._strings = {}

    def uleb128(self, off):
        d = self.data; r = 0; s = 0
        while True:
            b = d[off]; off += 1
            r |= (b & 0x7f) << s
            if not b & 0x80: return r, off
            s += 7

    def string_at(self, idx):
        if idx in self._strings: return self._strings[idx]
        off = struct.unpack_from('<I', self.data, self.string_ids_off + idx * 4)[0]
        n, p = self.uleb128(off)          # utf16 length
        end = self.data.index(b'\x00', p)
        s = self.data[p:end].decode('utf-8', 'replace')
        self._strings[idx] = s
        return s

    def type_name(self, idx):
        si = struct.unpack_from('<I', self.data, self.type_ids_off + idx * 4)[0]
        return self.string_at(si)

    def find_string_idx(self, target):
        out = []
        for i in range(self.string_ids_size):
            if self.string_at(i) == target: out.append(i)
        return out

    def class_defs(self):
        d = self.data
        for i in range(self.class_defs_size):
            off = self.class_defs_off + i * 32
            class_idx, _acc, _sup, _ifaces, _src, _ann, class_data_off, _sv = struct.unpack_from('<8I', d, off)
            yield i, class_idx, class_data_off

    def methods_of(self, class_data_off):
        """yield (method_idx, code_off)"""
        d = self.data
        if class_data_off == 0: return
        p = class_data_off
        sf, p = self.uleb128(p)
        inf, p = self.uleb128(p)
        dm, p = self.uleb128(p)
        vm, p = self.uleb128(p)
        for _ in range(sf):
            _, p = self.uleb128(p); _, p = self.uleb128(p)
        for _ in range(inf):
            _, p = self.uleb128(p); _, p = self.uleb128(p)
        for count in (dm, vm):
            idx = 0
            for _ in range(count):
                diff, p = self.uleb128(p)
                idx += diff
                _acc, p = self.uleb128(p)
                code_off, p = self.uleb128(p)
                if code_off: yield idx, code_off

    def code_range(self, code_off):
        d = self.data
        _regs, _ins, _outs, _tries, _dbg, insns_size = struct.unpack_from('<4H2I', d, code_off)
        start = code_off + 16
        return start, insns_size * 2

    def method_name(self, method_idx):
        d = self.data
        class_idx, _proto, name_idx = struct.unpack_from('<HHI', d, self.method_ids_off + method_idx * 8)
        return self.type_name(class_idx), self.string_at(name_idx)


def scan(apk_dir, targets):
    hits = {}
    for f in sorted(glob.glob(os.path.join(apk_dir, 'classes*.dex'))):
        dex = Dex(f)
        idxs = {}
        for t in targets:
            for i in dex.find_string_idx(t):
                idxs.setdefault(i, t)
        if not idxs: continue
        for ci, class_idx, cdoff in dex.class_defs():
            if not cdoff: continue
            cname = dex.type_name(class_idx)
            for midx, code_off in dex.methods_of(cdoff):
                s, ln = dex.code_range(code_off)
                chunk = dex.data[s:s + ln]
                for si, t in idxs.items():
                    found = False
                    if si <= 0xFFFF:
                        pat = struct.pack('<H', si)
                        pos = 0
                        while True:
                            pos = chunk.find(pat, pos)
                            if pos < 0: break
                            if pos >= 2 and pos % 2 == 0 and chunk[pos - 2] == 0x1a:
                                found = True; break
                            pos += 1
                    if not found:
                        # jumbo: 1b XX ii ii ii ii
                        pat4 = struct.pack('<I', si)
                        pos = 0
                        while True:
                            pos = chunk.find(pat4, pos)
                            if pos < 0: break
                            if pos >= 2 and pos % 2 == 0 and chunk[pos - 2] == 0x1b:
                                found = True; break
                            pos += 1
                    if found:
                        mc, mn = dex.method_name(midx)
                        hits.setdefault(t, set()).add(f'{cname}->{mn}')
    return hits


if __name__ == '__main__':
    apk = sys.argv[1]
    targets = sys.argv[2:]
    h = scan(apk, targets)
    for t in targets:
        print(f'=== {t}')
        for c in sorted(h.get(t, [])):
            print('   ', c)
