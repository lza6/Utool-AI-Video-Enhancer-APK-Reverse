#!/usr/bin/env python3
"""Resolve ADRP+ADD string/data xrefs in an ARM64 ELF, print string -> referencing code addresses."""
import sys
import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM


def load(path):
    b = lief.parse(path)
    secs = {s.name: s for s in b.sections}
    return b, secs


def sec_bytes(sec):
    return bytes(sec.content), sec.virtual_address


def read_cstr(b, vaddr, limit=160):
    for s in b.sections:
        if s.size and s.virtual_address <= vaddr < s.virtual_address + s.size:
            off = vaddr - s.virtual_address
            data = bytes(s.content)
            e = data.find(b'\0', off)
            if e < 0:
                e = min(off + limit, len(data))
            try:
                return data[off:e].decode('utf-8')
            except Exception:
                return None
    return None


def main(path, only=None):
    b, secs = load(path)
    code_secs = [secs['.text']] + ([secs['.plt']] if '.plt' in secs else [])
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    xrefs = {}
    for sec in code_secs:
        data, base = sec_bytes(sec)
        regs = {}
        for ins in md.disasm(data, base):
            m = ins.mnemonic
            if m == 'adrp' and len(ins.operands) == 2 and ins.operands[0].type == ARM64_OP_REG:
                r = ins.reg_name(ins.operands[0].reg)
                regs[r] = ins.operands[1].imm
            elif m in ('add', 'ldr') and len(ins.operands) >= 3:
                d, s = ins.operands[0], ins.operands[1]
                if s.type == ARM64_OP_REG and ins.reg_name(s.reg) in regs:
                    r = ins.reg_name(s.reg)
                    if m == 'add' and ins.operands[2].type == ARM64_OP_IMM:
                        tgt = regs[r] + ins.operands[2].imm
                        xrefs.setdefault(tgt, []).append(ins.address)
                    elif m == 'ldr' and ins.operands[2].type == ARM64_OP_IMM:
                        tgt = regs[r] + ins.operands[2].imm
                        xrefs.setdefault(tgt, []).append(ins.address)
            elif m in ('bl', 'blr', 'ret', 'b'):
                regs.clear()
    out = []
    for tgt, addrs in xrefs.items():
        s = read_cstr(b, tgt)
        if s is None:
            continue
        if only and only not in s:
            continue
        if not s or len(s) > 120:
            continue
        out.append((s, tgt, addrs))
    for s, tgt, addrs in sorted(out):
        print(f'{tgt:#08x}  {s!r}')
        for a in addrs[:6]:
            print(f'        ref {a:#08x}')


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
