#!/usr/bin/env python3
import argparse
import os

# pwntools grabs the terminal (hides the cursor, custom modes) when imported on
# a TTY, and a gdb spawned from us inherits that broken state. We only use it
# as an ELF parser, so opt out *before* the import below.
os.environ.setdefault("PWNLIB_NOTERM", "1")
import shutil
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field

import capstone as _cs
from capstone import (
    Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_MIPS,
    CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB,
    CS_MODE_MIPS32, CS_MODE_MIPS64, CS_MODE_BIG_ENDIAN,
    CS_OP_IMM, CS_OP_MEM, CS_OP_REG,
)

# --- capstone 5.x <-> 6.x compatibility -----------------------------------
# 6.x renamed CS_ARCH_ARM64 -> CS_ARCH_AARCH64; RISC-V constants may be absent
# on old builds, in which case RISC-V stripped analysis is simply disabled.
CS_ARCH_AARCH64 = getattr(_cs, "CS_ARCH_AARCH64", getattr(_cs, "CS_ARCH_ARM64", None))
CS_ARCH_RISCV = getattr(_cs, "CS_ARCH_RISCV", None)
CS_MODE_RISCV32 = getattr(_cs, "CS_MODE_RISCV32", None)
CS_MODE_RISCV64 = getattr(_cs, "CS_MODE_RISCV64", None)
CS_MODE_RISCVC = getattr(_cs, "CS_MODE_RISCVC", None)
CS_ARCH_SYSTEMZ = getattr(_cs, "CS_ARCH_SYSTEMZ", getattr(_cs, "CS_ARCH_SYSZ", None))
CS_ARCH_PPC = getattr(_cs, "CS_ARCH_PPC", None)
HAVE_RISCV = None not in (CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCV64, CS_MODE_RISCVC)
from capstone.x86_const import X86_REG_RIP
from capstone.arm_const import ARM_REG_PC
from colorama import Fore, Style, init
from pwn import ELF, context

init()
G = Fore.GREEN + Style.BRIGHT
R = Fore.RED + Style.BRIGHT
Y = Fore.YELLOW + Style.BRIGHT
C = Fore.CYAN + Style.BRIGHT
RS = Style.RESET_ALL

context.log_level = "critical"

# --------------------------------------------------------------------------
# register bookkeeping: _FULL = registers whose value we track (32/64-bit),
# _ANY = every alias (al, ax, edi, rdi ...) -> canonical 64-bit name
# --------------------------------------------------------------------------
_FULL, _ANY = set(), {}
for _a in "abcd":
    for _n in (f"r{_a}x", f"e{_a}x"):
        _FULL.add(_n)
        _ANY[_n] = f"r{_a}x"
    for _n in (f"{_a}x", f"{_a}l", f"{_a}h"):
        _ANY[_n] = f"r{_a}x"
for _a in ("si", "di", "bp", "sp"):
    for _n in (f"r{_a}", f"e{_a}"):
        _FULL.add(_n)
        _ANY[_n] = f"r{_a}"
    for _n in (_a, f"{_a}l"):
        _ANY[_n] = f"r{_a}"
for _i in range(8, 16):
    for _s in ("", "d"):
        _FULL.add(f"r{_i}{_s}")
        _ANY[f"r{_i}{_s}"] = f"r{_i}"
    for _s in ("w", "b"):
        _ANY[f"r{_i}{_s}"] = f"r{_i}"

# Mnemonics whose FIRST register operand is a source (stores, compares, branches), not a
# destination. Treating it as a destination made the tracers "forget" a register the
# program merely spilled to the stack. Prefix tuples for big families, exact sets otherwise.
NO_DST_ARM = ("str", "cmp", "cmn", "tst", "teq", "push", "stm", "vstr", "vst", "cbz", "cbnz")
NO_DST_A64 = ("st", "cmp", "cmn", "tst", "ccmp", "ccmn", "cbz", "cbnz", "tbz", "tbnz", "prfm")
NO_DST_MIPS = {"sw", "sd", "sb", "sh", "sc", "swl", "swr", "sdl", "sdr", "swc1", "sdc1", "beq", "bne",
               "blez", "bgtz", "bltz", "bgez", "beqz", "bnez", "b", "j", "jr"}
NO_DST_RV = {"sd", "sw", "sb", "sh", "fsd", "fsw", "beq", "bne", "blt", "bge", "bltu", "bgeu",
             "beqz", "bnez", "blez", "bgez", "bltz", "bgtz"}
NO_DST_PPC = ("st", "cmp", "mt", "b", "tw", "td", "cr")
NO_DST_S390 = ("st", "c", "j", "b")

CALLER_SAVED = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")


@dataclass
class Found:
    addr: int
    method: str
    confidence: str
    notes: list = field(default_factory=list)
    thumb: bool = False


class ElfHelpers:
    """Shared ELF-level plumbing: exec-segment lookup, RELATIVE-reloc-aware
    pointer reads, and locating __libc_start_main's symbol/PLT/GOT addresses.
    pwntools already abstracts symbols/plt/got uniformly across archs, so
    this class needs no per-arch special-casing beyond the RELATIVE reloc's
    numeric type (used by PIE binaries to pre-fill GOT slots)."""

    REL_RELATIVE_TYPE = None  # set per architecture subclass

    def __init__(self, elf, verbose=False):
        self.elf, self.verbose = elf, verbose
        self.bits = elf.bits
        self.mask = (1 << self.bits) - 1
        self.psz = self.bits // 8
        self.exec_ranges = [
            (s.header.p_vaddr, s.header.p_vaddr + s.header.p_memsz)
            for s in elf.segments
            if s.header.p_type == "PT_LOAD" and s.header.p_flags & 1
        ]
        self.load_ranges = [
            (s.header.p_vaddr, s.header.p_vaddr + s.header.p_filesz)
            for s in elf.segments if s.header.p_type == "PT_LOAD"
        ]
        # The ELF header + program-header table sit at the start of the first segment
        # (vaddr 0 in a PIE). It is mapped executable but is never a function.
        hdr_len = elf.header.e_ehsize + elf.header.e_phnum * elf.header.e_phentsize
        self.hdr_ranges = [(s.header.p_vaddr, s.header.p_vaddr + hdr_len)
                           for s in elf.segments if s.header.p_type == "PT_LOAD" and s.header.p_offset == 0]
        self.relative = self._load_relative_relocs()
        self.libc_start, self.libc_slots = self._libc_start_refs()

    def mapped(self, a, n=1):
        return any(lo <= a and a + n <= hi for lo, hi in self.load_ranges)

    def _load_relative_relocs(self):
        """{slot vaddr: addend} for RELATIVE relocations that carry an explicit addend (RELA).
        REL-style relocs keep the addend in the slot itself, so a raw read already works."""
        rel = {}
        if self.REL_RELATIVE_TYPE is None:
            return rel
        for name in (".rela.dyn", ".rel.dyn"):                 # normal case: via section headers
            sec = self.elf.get_section_by_name(name)
            if not sec:
                continue
            try:
                for r in sec.iter_relocations():
                    if r["r_info_type"] == self.REL_RELATIVE_TYPE and "r_addend" in r.entry:
                        rel[r["r_offset"]] = r["r_addend"] & self.mask
            except Exception:
                pass
        if not rel:                                            # sectionless / sstripped binary
            rel = self._relative_from_dynamic()
        return rel

    def _relative_from_dynamic(self):
        rel = {}
        try:
            dyn = next(sg for sg in self.elf.segments if sg.header.p_type == "PT_DYNAMIC")
            raw = self.elf.read(dyn.header.p_vaddr, dyn.header.p_filesz)
            e, w = self.elf.endian, self.psz
            tags = {}
            for i in range(0, len(raw) - 2 * w + 1, 2 * w):
                tag = int.from_bytes(raw[i:i + w], e, signed=True)
                if tag == 0:                                   # DT_NULL
                    break
                tags.setdefault(tag, int.from_bytes(raw[i + w:i + 2 * w], e))
            DT_RELA, DT_RELASZ, DT_RELAENT = 7, 8, 9
            if DT_RELA in tags and DT_RELASZ in tags:
                ent = tags.get(DT_RELAENT, 3 * w)
                blob = self.elf.read(tags[DT_RELA], tags[DT_RELASZ])
                for i in range(0, len(blob) - ent + 1, ent):
                    off = int.from_bytes(blob[i:i + w], e)
                    info = int.from_bytes(blob[i + w:i + 2 * w], e)
                    add = int.from_bytes(blob[i + 2 * w:i + 3 * w], e, signed=True)
                    rtype = (info & 0xFFFFFFFF) if w == 8 else (info & 0xFF)
                    if rtype == self.REL_RELATIVE_TYPE:
                        rel[off] = add & self.mask
        except Exception:
            pass
        return rel

    def _libc_start_refs(self):
        addrs, slots = set(), set()
        for name in ("__libc_start_main", "__libc_start_main_impl"):
            for table, dest in ((self.elf.symbols, addrs), (self.elf.plt, addrs), (self.elf.got, slots)):
                try:
                    v = table.get(name)
                except Exception:
                    v = None
                if v:
                    dest.add(v)
        return addrs, slots

    def is_exec(self, a):
        if a is None or any(lo <= a < hi for lo, hi in self.hdr_ranges):
            return False
        return any(lo <= a < hi for lo, hi in self.exec_ranges)

    def _code(self, addr, n=0x100):
        while n >= 0x10:
            if self.mapped(addr, n):
                try:
                    return self.elf.read(addr, n)
                except Exception:
                    pass
            n //= 2
        return b""

    def _read_ptr(self, slot, size=None):
        size = size or self.psz
        if slot in self.relative:  # PIE: GOT slot is filled by a RELATIVE reloc
            return self.relative[slot]
        if slot is None or not self.mapped(slot, size):
            return None
        try:
            return int.from_bytes(self.elf.read(slot, size), self.elf.endian)
        except Exception:
            return None


class X86Tracer(ElfHelpers):
    REL_RELATIVE_TYPE = 8  # R_X86_64_RELATIVE == R_386_RELATIVE

    def __init__(self, elf, verbose=False):
        super().__init__(elf, verbose)
        self.md = Cs(CS_ARCH_X86, CS_MODE_64 if self.bits == 64 else CS_MODE_32)
        self.md.detail = True

    def _ea(self, insn, mem, regs):
        if mem.segment or mem.index:
            return None
        if mem.base == 0:
            base = 0
        elif mem.base == X86_REG_RIP:
            base = insn.address + insn.size
        else:
            base = regs.get(_ANY.get(insn.reg_name(mem.base), ""))
            if base is None:
                return None
        return (base + mem.disp) & self.mask

    def _val(self, insn, op, regs):
        if op.type == CS_OP_IMM:
            return op.imm & self.mask
        if op.type == CS_OP_REG:
            n = insn.reg_name(op.reg)
            return regs.get(_ANY[n]) if n in _FULL else None
        if op.type == CS_OP_MEM:
            slot = self._ea(insn, op.mem, regs)
            return self._read_ptr(slot) if slot is not None else None
        return None

    def _branch_target(self, insn, regs):
        """-> (target address or None, GOT slot or None)"""
        if not insn.operands:
            return None, None
        op = insn.operands[0]
        if op.type == CS_OP_IMM:
            return op.imm & self.mask, None
        if op.type == CS_OP_MEM:
            slot = self._ea(insn, op.mem, regs)
            return (self._read_ptr(slot) if slot is not None else None), slot
        if op.type == CS_OP_REG:
            return regs.get(_ANY.get(insn.reg_name(op.reg), "")), None
        return None, None

    def _pc_thunk(self, addr):
        """i386 __x86.get_pc_thunk.<reg>: `mov reg,[esp]; ret` -> canonical reg."""
        if not self.is_exec(addr):
            return None
        ins = list(self.md.disasm(self._code(addr, 0x10), addr, 2))
        if len(ins) == 2 and ins[0].mnemonic == "mov" and ins[1].mnemonic == "ret":
            d, s = ins[0].operands
            if d.type == CS_OP_REG and s.type == CS_OP_MEM and ins[0].reg_name(s.mem.base) == "esp" and s.mem.disp == 0:
                return _ANY.get(ins[0].reg_name(d.reg))
        return None

    # ---------------------------------------------------------- core
    # Control-flow aware: unconditional jumps are followed, conditional jumps fork the
    # register state (so both a loop body AND its exit are explored), and every path is
    # bounded by a per-address visit limit and a global instruction budget. This is needed
    # for start-up code with real loops, e.g. musl static-PIE inlines its self-relocation
    # loop into _start_c before it ever reaches `lea rdi, main`.
    def trace(self, start, depth=0, until=None):
        if depth == 0:
            self._left = 4000 if until is None else 400      # instruction budget for the whole search
        visits = Counter()
        work = [(start, {}, [])]
        while work and self._left > 0:
            addr, regs, stack = work.pop()
            r = self._walk(addr, regs, stack, depth, until, work, visits)
            if r:
                return r
        return None

    def _walk(self, addr, regs, stack, depth, until, work, visits):
        while self._left > 0:
            code = self._code(addr)
            if not code:
                return None
            next_addr = None
            for insn in self.md.disasm(code, addr):
                self._left -= 1
                visits[insn.address] += 1
                if self._left <= 0 or visits[insn.address] > 3:      # budget / loop guard
                    return None
                m, ops = insn.mnemonic, insn.operands
                if self.verbose:
                    print(f"    {insn.address:#x}: {m} {insn.op_str}", file=sys.stderr)

                # conditional jump: explore the taken edge later, keep going on the fall-through
                if m[0] == "j" and m != "jmp" and ops and ops[0].type == CS_OP_IMM:
                    work.append((ops[0].imm & self.mask, dict(regs), list(stack)))
                    continue

                if m in ("call", "jmp"):
                    tgt, slot = self._branch_target(insn, regs)
                    if m == "call" and self.bits == 32 and tgt is not None:
                        r = self._pc_thunk(tgt)
                        if r:
                            regs[r] = (insn.address + insn.size) & self.mask
                            continue
                    cand = regs.get("rdi") if self.bits == 64 else (stack[-1] if stack else None)
                    is_start = (tgt in self.libc_start) or (slot in self.libc_slots)
                    at_site = until is None or insn.address == until
                    if cand is not None and self.is_exec(cand) and cand != self.elf.entry and at_site:
                        what = "__libc_start_main" if is_start else "an internal call"
                        return Found(cand, f"_start trace: main passed at {insn.address:#x} to {what}",
                                     "high" if is_start else "medium")
                    if until is not None and insn.address >= until:
                        return None
                    if m == "jmp":
                        if ops and ops[0].type == CS_OP_IMM and self.is_exec(tgt) and not is_start:
                            next_addr = tgt                  # follow the jump inside this function
                            break
                        return None                          # indirect jump / tail call: path ends
                    if until is None and depth < 2 and tgt and self.is_exec(tgt) and not is_start:
                        r = self.trace(tgt, depth + 1)       # e.g. musl: _start -> _start_c
                        if r:
                            return r
                    for r in CALLER_SAVED:
                        regs.pop(r, None)
                    stack.clear()
                    continue

                if m in ("ret", "hlt", "ud2"):
                    return None

                new = {}
                dreg = None
                if ops and ops[0].type == CS_OP_REG:
                    n = insn.reg_name(ops[0].reg)
                    if n in _FULL:
                        dreg = _ANY[n]

                if m in ("mov", "movabs") and dreg and len(ops) == 2:
                    new[dreg] = self._val(insn, ops[1], regs)
                elif m == "lea" and dreg and len(ops) == 2:
                    new[dreg] = self._ea(insn, ops[1].mem, regs)
                elif m in ("add", "sub") and dreg and len(ops) == 2:
                    cur, v = regs.get(dreg), self._val(insn, ops[1], regs)
                    if cur is not None and v is not None:
                        new[dreg] = ((cur + v) if m == "add" else (cur - v)) & self.mask
                elif m == "xor" and dreg and len(ops) == 2 and ops[1].type == CS_OP_REG and ops[1].reg == ops[0].reg:
                    new[dreg] = 0
                elif m == "push" and ops:
                    stack.append(self._val(insn, ops[0], regs))
                elif m == "pop":
                    v = stack.pop() if stack else None
                    if dreg:
                        new[dreg] = v

                try:  # anything we don't model but that writes a register -> unknown
                    for r in insn.regs_access()[1]:
                        regs.pop(_ANY.get(insn.reg_name(r), ""), None)
                except Exception:
                    pass
                regs.update({k: v for k, v in new.items() if v is not None})
            if next_addr is None:
                return None
            addr = next_addr
        return None

    def scan(self):
        """Find every `call __libc_start_main` in exec segments, trace back from each."""
        sites = []
        for lo, hi in self.exec_ranges:
            try:
                data = self.elf.read(lo, min(hi - lo, 64 << 20))
            except Exception:
                continue
            if self.bits == 64 and self.libc_slots:
                i = data.find(b"\xff\x15")
                while i != -1 and i + 6 <= len(data):
                    if (lo + i + 6 + struct.unpack_from("<i", data, i + 2)[0]) in self.libc_slots:
                        sites.append(lo + i)
                    i = data.find(b"\xff\x15", i + 1)
            if self.libc_start:
                i = data.find(b"\xe8")
                while i != -1 and i + 5 <= len(data):
                    if ((lo + i + 5 + struct.unpack_from("<i", data, i + 1)[0]) & self.mask) in self.libc_start:
                        sites.append(lo + i)
                    i = data.find(b"\xe8", i + 1)
        votes = Counter()
        for site in sites:
            for k in range(0x08, 0x90):  # unknown function start: try every offset
                r = self.trace(site - k, until=site)
                if r:
                    votes[r.addr] += 1
        if votes:
            addr, _ = votes.most_common(1)[0]
            return Found(addr, f"code scan: call to __libc_start_main at {sites[0]:#x}", "medium",
                         ["entry point did not lead to main; found by scanning call sites"])
        return None


# ==========================================================================
# ARM (A32 + Thumb2)
#
# glibc's ARM _start/crt loads main's address through a small, very
# consistent idiom, whether the binary is PIE or not:
#     ldr   r10, [pc, #24]      ; r10 = literal: GOT_base - here   (word)
#     add   r10, pc             ; r10 = runtime GOT base           (ADR-ish)
#     ldr   r0,  [pc, #16]      ; r0  = literal: offset of main's GOT slot
#     ldr   r0,  [r10, r0]      ; r0  = *(GOT_base + offset) = main
#     bl    __libc_start_main
# Both PC-relative literal loads and ADR/ADD-PC use the same effective PC:
# Align(insn.address + 4, 4) -- true for both 16-bit and 32-bit (.w) Thumb
# encodings, and confirmed against objdump on real glibc-linked binaries.
# ==========================================================================
_ARM_ALIAS = {"sl": "r10", "fp": "r11", "ip": "r12", "sp": "r13", "lr": "r14", "pc": "r15"}


class ArmTracer(ElfHelpers):
    REL_RELATIVE_TYPE = 23  # R_ARM_RELATIVE
    ARG_REG = "r0"

    def __init__(self, elf, verbose=False):
        super().__init__(elf, verbose)
        thumb = elf.entry & 1
        self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
        self.md.detail = True
        self.pc_bias = 4 if thumb else 8   # ARM ISA: PC reads as insn addr + 8/4
        self.align_pc = bool(thumb)        # Thumb literal loads use Align(PC,4)
        self.thumb = bool(thumb)

    def _reg(self, insn, r):
        n = insn.reg_name(r)
        return _ARM_ALIAS.get(n, n)

    def _pc_val(self, insn):
        pc = insn.address + self.pc_bias
        return pc & ~3 if self.align_pc else pc

    def _ea(self, insn, mem, regs):
        if mem.base == ARM_REG_PC:
            base = self._pc_val(insn)
        elif mem.base:
            base = regs.get(self._reg(insn, mem.base))
            if base is None:
                return None
        else:
            base = 0
        if mem.index:
            idx = regs.get(self._reg(insn, mem.index))
            if idx is None:
                return None
            sign = -1 if getattr(mem, "scale", 1) == -1 else 1     # ARM: scale is the index sign (+1/-1)
            base += sign * (idx << (getattr(mem, "lshift", 0) or 0))
        return (base + mem.disp) & self.mask

    def trace(self, start, until=None):
        start &= ~1  # clear the ISA-mode bit; it's not part of the address
        regs, written = {}, set()
        try:
            insns = list(self.md.disasm(self._code(start, 0x200), start))
        except Exception:
            return None
        for insn in insns:
            m, ops = insn.mnemonic.removesuffix(".w"), insn.operands
            if self.verbose:
                print(f"    {insn.address:#x}: {insn.mnemonic} {insn.op_str}", file=sys.stderr)

            if m in ("bl", "blx", "bx") or (m == "b" and insn.address != start):
                tgt = ops[0].imm if ops and ops[0].type == CS_OP_IMM else None
                if tgt is None and ops and ops[0].type == CS_OP_REG:
                    tgt = regs.get(self._reg(insn, ops[0].reg))
                is_start = tgt in self.libc_start
                cand = regs.get(self.ARG_REG)
                at_site = until is None or insn.address == until
                if cand is not None and self.is_exec(cand) and cand != self.elf.entry and at_site:
                    what = "__libc_start_main" if is_start else "an internal call"
                    return Found(cand, f"_start trace: main passed at {insn.address:#x} to {what}",
                                 "high" if is_start else "medium")
                if until is not None and insn.address >= until:
                    return None
                if m == "bl" and not is_start and tgt and self.is_exec(tgt) and until is None:
                    r = self.trace(tgt)
                    if r:
                        return r
                if m in ("b", "bx"):
                    return None
                if until is None and (is_start or self.ARG_REG in written):
                    return None      # __libc_start_main never returns: what follows is a different function
                continue

            if m in ("pop", "ldm", "ldmfd") and any(self._reg(insn, o.reg) in ("r15", "r14") for o in ops if o.type == CS_OP_REG):
                return None

            dst = self._reg(insn, ops[0].reg) if ops and ops[0].type == CS_OP_REG and not m.startswith(NO_DST_ARM) else None
            val = None
            if m in ("mov", "movs") and len(ops) == 2 and not self._shifted(ops[1]):
                val = self._val_of(insn, ops[1], regs)
            elif m == "movt" and len(ops) == 2 and dst:
                cur = regs.get(dst, 0) or 0
                val = (cur & 0xFFFF) | ((ops[1].imm & 0xFFFF) << 16)
            elif m == "movw" and len(ops) == 2:
                val = ops[1].imm & 0xFFFF
            elif m == "adr" and len(ops) == 2:
                val = (self._pc_val(insn) + ops[1].imm) & self.mask
            elif m in ("add", "sub") and len(ops) == 2 and ops[1].type == CS_OP_REG:   # `add rd, rm` (rd is also src)
                a, b = regs.get(dst), self._val_of(insn, ops[1], regs)
                if a is not None and b is not None and not self._shifted(ops[1]):
                    val = ((a + b) if m == "add" else (a - b)) & self.mask
            elif m in ("add", "sub") and len(ops) == 3:
                a, b = self._val_of(insn, ops[1], regs), self._val_of(insn, ops[2], regs)
                if a is not None and b is not None and not self._shifted(ops[1]) and not self._shifted(ops[2]):
                    val = ((a + b) if m == "add" else (a - b)) & self.mask
            elif m == "ldr" and len(ops) == 2 and ops[0].type == CS_OP_REG and ops[1].type == CS_OP_MEM:
                slot = self._ea(insn, ops[1].mem, regs)
                val = self._read_ptr(slot) if slot is not None else None

            if dst:
                written.add(dst)
                if val is not None:
                    regs[dst] = val
                else:
                    regs.pop(dst, None)
            wb = next((o for o in ops if o.type == CS_OP_MEM), None)
            if wb is not None and getattr(insn, "writeback", False) and wb.mem.base:
                regs.pop(self._reg(insn, wb.mem.base), None)   # base register was modified
        return None

    @staticmethod
    def _shifted(op):
        """True if a register operand carries a barrel-shifter operation (we don't model those)."""
        try:
            return bool(op.shift.type)
        except Exception:
            return False

    def _val_of(self, insn, op, regs):
        if op.type == CS_OP_IMM:
            return op.imm & self.mask
        if op.type == CS_OP_REG:
            n = self._reg(insn, op.reg)          # canonical: pc -> r15, sl -> r10, ...
            return self._pc_val(insn) if n == "r15" else regs.get(n)
        return None

    def _set_mode(self, thumb):
        self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
        self.md.detail = True
        self.pc_bias = 4 if thumb else 8
        self.align_pc = bool(thumb)
        self.thumb = bool(thumb)

    def scan(self):
        """Entry may be tampered, so try both ISA modes (Thumb first: modern
        ARM Linux userland is overwhelmingly Thumb-2)."""
        original = self.thumb
        for thumb in (True, False):
            self._set_mode(thumb)
            r = self._scan_mode()
            if r:
                r.thumb = thumb
                return r
        self._set_mode(original)
        return None

    def _scan_mode(self):
        votes = Counter()
        step = 2 if self.thumb else 4
        for lo, hi in self.exec_ranges:
            try:
                data = self.elf.read(lo, min(hi - lo, 32 << 20))
            except Exception:
                continue
            for off in range(0, len(data) - 4, step):
                try:
                    ins = next(self.md.disasm(data[off:off + 4], lo + off))
                except StopIteration:
                    continue
                if ins.mnemonic not in ("bl", "blx") or not ins.operands:
                    continue
                op = ins.operands[0]
                if op.type != CS_OP_IMM or op.imm not in self.libc_start:
                    continue
                site = lo + off
                for k in range(0x08, 0xA0, step):
                    r = self.trace(site - k, until=site)
                    if r and r.confidence == "high":
                        votes[r.addr] += 1
        if votes:
            addr, _ = votes.most_common(1)[0]
            return Found(addr, "code scan: call to __libc_start_main", "medium",
                         ["entry point did not lead to main; found by scanning call sites"])
        return None


# ==========================================================================
# AArch64
#   PIE:    adrp x0, page ; ldr x0, [x0, #imm]     (GOT-indirect, dereference)
#   non-PIE:adrp x0, page ; add x0, x0, #imm        (direct address)
# capstone resolves ADRP's immediate operand to the already page-aligned
# target address, matching what objdump shows.
# ==========================================================================
class Arm64Tracer(ElfHelpers):
    REL_RELATIVE_TYPE = 1027  # R_AARCH64_RELATIVE
    ARG_REG = "x0"

    def __init__(self, elf, verbose=False):
        super().__init__(elf, verbose)
        self.md = Cs(CS_ARCH_AARCH64, 0)
        self.md.detail = True

    def _reg(self, insn, r):
        n = insn.reg_name(r)
        return "x" + n[1:] if n and n[0] == "w" else n  # treat w-regs as their x alias

    def trace(self, start, until=None, depth=0):
        regs, written = {}, set()
        try:
            insns = list(self.md.disasm(self._code(start, 0x200), start))
        except Exception:
            return None
        for insn in insns:
            m, ops = insn.mnemonic, insn.operands
            if self.verbose:
                print(f"    {insn.address:#x}: {m} {insn.op_str}", file=sys.stderr)

            if m in ("bl", "b") and ops and ops[0].type == CS_OP_IMM:
                tgt = ops[0].imm & self.mask
                is_start = tgt in self.libc_start
                cand = regs.get(self.ARG_REG)
                at_site = until is None or insn.address == until
                if cand is not None and self.is_exec(cand) and cand != self.elf.entry and at_site:
                    what = "__libc_start_main" if is_start else "an internal call"
                    return Found(cand, f"_start trace: main passed at {insn.address:#x} to {what}",
                                 "high" if is_start else "medium")
                if until is not None and insn.address >= until:
                    return None
                if until is None and depth < 2 and not is_start and self.is_exec(tgt):
                    r = self.trace(tgt, depth=depth + 1)      # e.g. musl: _start -> _start_c
                    if r:
                        return r
                if m == "b":
                    return None
                if until is None and (is_start or self.ARG_REG in written):
                    return None      # __libc_start_main never returns: what follows is a different function
                continue
            if m in ("ret", "br"):
                return None

            dst = self._reg(insn, ops[0].reg) if ops and ops[0].type == CS_OP_REG and not m.startswith(NO_DST_A64) else None
            val = None
            if m == "adrp" and len(ops) == 2 and ops[1].type == CS_OP_IMM:
                val = ops[1].imm & self.mask
            elif m in ("mov", "movz") and len(ops) == 2 and ops[1].type == CS_OP_IMM:
                val = ops[1].imm & self.mask
            elif m == "movk" and len(ops) == 2 and dst:
                cur = regs.get(dst, 0) or 0
                shift = insn.op_str.split("lsl")[-1] if "lsl" in insn.op_str else "#0"
                try:
                    sh = int(shift.strip().lstrip("#"), 0)
                except ValueError:
                    sh = 0
                val = (cur & ~(0xFFFF << sh)) | ((ops[1].imm & 0xFFFF) << sh)
            elif m == "add" and len(ops) == 3 and ops[2].type == CS_OP_IMM:
                base = regs.get(self._reg(insn, ops[1].reg))
                imm = ops[2].imm << 12 if "lsl #12" in insn.op_str.replace("lsl #0xc", "lsl #12") else ops[2].imm
                val = (base + imm) & self.mask if base is not None else None
            elif m in ("mov",) and len(ops) == 2 and ops[1].type == CS_OP_REG:
                val = regs.get(self._reg(insn, ops[1].reg))
            elif m == "ldr" and len(ops) == 2 and ops[1].type == CS_OP_IMM:   # literal: ldr x0, <addr>
                dn = insn.reg_name(ops[0].reg)
                val = self._read_ptr(ops[1].imm & self.mask, 4 if dn and dn[0] == "w" else 8)
            elif m in ("ldr",) and len(ops) == 2 and ops[1].type == CS_OP_MEM:
                mem = ops[1].mem
                base = regs.get(self._reg(insn, mem.base)) if mem.base else 0
                if base is not None:
                    slot = (base + mem.disp) & self.mask
                    dreg_name = insn.reg_name(ops[0].reg)
                    sz = 4 if dreg_name and dreg_name[0] == "w" else 8
                    val = self._read_ptr(slot, size=sz)

            if dst:
                written.add(dst)
                if val is not None:
                    regs[dst] = val
                else:
                    regs.pop(dst, None)
            wb = next((o for o in ops if o.type == CS_OP_MEM), None)
            if wb is not None and getattr(insn, "writeback", False) and wb.mem.base:
                regs.pop(self._reg(insn, wb.mem.base), None)   # base register was modified
        return None

    def scan(self):
        votes = Counter()
        for lo, hi in self.exec_ranges:
            try:
                data = self.elf.read(lo, min(hi - lo, 32 << 20))
            except Exception:
                continue
            for off in range(0, len(data) - 4, 4):
                try:
                    ins = next(self.md.disasm(data[off:off + 4], lo + off))
                except StopIteration:
                    continue
                if ins.mnemonic != "bl" or not ins.operands or ins.operands[0].type != CS_OP_IMM:
                    continue
                if ins.operands[0].imm not in self.libc_start:
                    continue
                site = lo + off
                for k in range(0x08, 0xA0, 4):
                    r = self.trace(site - k, until=site)
                    if r:
                        votes[r.addr] += 1
        if votes:
            addr, _ = votes.most_common(1)[0]
            return Found(addr, "code scan: call to __libc_start_main", "medium",
                         ["entry point did not lead to main; found by scanning call sites"])
        return None


# ==========================================================================
# MIPS (O32, 32-bit, little/big endian) - the common case for crackmes.
# glibc crt0 idiom:
#   bal L; nop            ; ra = L  (self-referencing, used only to get PC)
#   L: lui gp,%hi(d); addiu gp,gp,%lo(d); addu gp,gp,ra   ; gp = runtime _gp
#   lw a0, off(gp)                                        ; a0 = *(gp+off) = main
#   ...
#   lw t9, off(gp); jalr t9                                ; call __libc_start_main
# Local GOT slots are pre-filled by the static linker with the plain
# (non-PIE) absolute address, so a raw file read of the slot is correct
# for the common non-PIE case crackmes.one binaries almost always use;
# true MIPS PIE would need the runtime load bias added on top.
# ==========================================================================
def _sext32(v):
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


def _sext16(v):
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


class MipsTracer(ElfHelpers):
    REL_RELATIVE_TYPE = None  # MIPS doesn't use a generic RELATIVE reloc for local GOT
    ARG_REG = "a0"

    def __init__(self, elf, verbose=False):
        super().__init__(elf, verbose)
        mode = (CS_MODE_MIPS64 if elf.bits == 64 else CS_MODE_MIPS32) | (CS_MODE_BIG_ENDIAN if elf.endian == "big" else 0)
        self.md = Cs(CS_ARCH_MIPS, mode)
        self.md.detail = True

    def trace(self, start, until=None):
        regs, written = {}, set()
        try:
            insns = list(self.md.disasm(self._code(start, 0x200), start))
        except Exception:
            return None
        for insn in insns:
            m, ops = insn.mnemonic, insn.operands
            if self.verbose:
                print(f"    {insn.address:#x}: {m} {insn.op_str}", file=sys.stderr)
            names = [insn.reg_name(o.reg) if o.type == CS_OP_REG else None for o in ops]

            if m in ("jalr", "jal", "bal"):
                if m == "bal":
                    regs["ra"] = (insn.address + 8) & self.mask
                    continue  # crt's gp-setup idiom: no real control-flow change
                tgt = ops[0].imm if (ops and ops[0].type == CS_OP_IMM) else (
                    regs.get(names[0]) if names and names[0] else None)
                is_start = tgt in self.libc_start
                cand = regs.get(self.ARG_REG)
                at_site = until is None or insn.address == until
                if cand is not None and self.is_exec(cand) and cand != self.elf.entry and at_site:
                    what = "__libc_start_main" if is_start else "an internal call"
                    return Found(cand, f"_start trace: main passed at {insn.address:#x} to {what}",
                                 "high" if is_start else "medium")
                if until is not None and insn.address >= until:
                    return None
                if until is None and (is_start or self.ARG_REG in written):
                    return None      # __libc_start_main never returns: what follows is a different function
                continue
            if m in ("jr",) and names and names[0] == "ra":
                return None

            dst = names[0] if ops and ops[0].type == CS_OP_REG and m not in NO_DST_MIPS else None
            val = None
            if m == "lui" and len(ops) == 2:
                val = _sext32((ops[1].imm & 0xFFFF) << 16) & self.mask
            elif m in ("addiu", "daddiu") and len(ops) == 3:
                rs = names[1]
                base = 0 if rs == "zero" else regs.get(rs)
                val = (base + _sext16(ops[2].imm)) & self.mask if base is not None else None
            elif m in ("addu", "add", "daddu", "dadd") and len(ops) == 3:
                a, b = regs.get(names[1]), regs.get(names[2])
                val = (a + b) & self.mask if (a is not None and b is not None) else None
            elif m == "move" and len(ops) == 2:
                val = regs.get(names[1])
            elif m in ("lw", "ld") and len(ops) == 2 and ops[1].type == CS_OP_MEM:
                mem = ops[1].mem
                base = 0 if mem.base == 0 else regs.get(insn.reg_name(mem.base))
                if base is not None:
                    slot = (base + mem.disp) & self.mask
                    val = self._read_ptr(slot, size=8 if m == "ld" else 4)

            if dst:
                written.add(dst)
                if val is not None:
                    regs[dst] = val
                else:
                    regs.pop(dst, None)
        return None

    def scan(self):
        """glibc calls __libc_start_main via `jalr t9` (t9 loaded from the GOT),
        older/static code via `jal`. Trace back from every call and keep only
        those whose target resolves to __libc_start_main."""
        votes = Counter()
        for lo, hi in self.exec_ranges:
            try:
                data = self.elf.read(lo, min(hi - lo, 32 << 20))
            except Exception:
                continue
            for off in range(0, len(data) - 4, 4):
                try:
                    ins = next(self.md.disasm(data[off:off + 4], lo + off))
                except StopIteration:
                    continue
                if ins.mnemonic not in ("jalr", "jal"):
                    continue
                site = lo + off
                for k in range(0x08, 0xC0, 4):
                    r = self.trace(site - k, until=site)
                    if r and r.confidence == "high":
                        votes[r.addr] += 1
        if votes:
            addr, _ = votes.most_common(1)[0]
            return Found(addr, "code scan: call to __libc_start_main", "medium",
                         ["entry point did not lead to main; found by scanning call sites"])
        return None


def chase_trampoline(elf, md, addr, branch_mnemonics, nop_mnemonics, is_exec, mask, max_hops=4):
    """Some modern glibc/binutils combos (notably AArch64 static-pie support)
    insert a one-instruction __wrap_main trampoline between _start and the
    user's real main: `nop; b main`. Follow direct unconditional branches so
    we report the real function, not the wrapper."""
    seen = set()
    for _ in range(max_hops):
        if addr in seen or not is_exec(addr):
            break
        seen.add(addr)
        try:
            code = elf.read(addr, 16)
        except Exception:
            break
        insns = list(md.disasm(code, addr))
        i = 0
        while i < len(insns) and insns[i].mnemonic in nop_mnemonics:
            i += 1
        if i >= len(insns):
            break
        insn = insns[i]
        if insn.mnemonic not in branch_mnemonics or not insn.operands:
            break
        op = insn.operands[0]
        if op.type != CS_OP_IMM:
            break
        # capstone 5 gives compressed RISC-V jumps (c.j) as PC-relative offsets
        addr = ((insn.address + op.imm) if insn.mnemonic.startswith("c.") else op.imm) & mask
    return addr


# ==========================================================================
# RISC-V (rv32 / rv64, compressed insns handled by capstone)
#   PIE:     auipc a0, hi ; ld a0, lo(a0)      (GOT-indirect -> dereference)
#   non-PIE: auipc a0, hi ; addi a0, a0, lo    (direct address)
#   jal ra, __libc_start_main@plt
# ==========================================================================
class RiscvTracer(ElfHelpers):
    REL_RELATIVE_TYPE = 3  # R_RISCV_RELATIVE
    ARG_REG = "a0"

    def __init__(self, elf, verbose=False):
        super().__init__(elf, verbose)
        mode = (CS_MODE_RISCV64 if self.bits == 64 else CS_MODE_RISCV32) | CS_MODE_RISCVC
        self.md = Cs(CS_ARCH_RISCV, mode)
        self.md.detail = True

    @staticmethod
    def _upper(imm20):
        """(imm20 << 12) as a signed 32-bit quantity, as the ISA defines for lui/auipc."""
        v = (imm20 & 0xFFFFF) << 12
        return v - (1 << 32) if v & 0x80000000 else v

    def trace(self, start, until=None):
        regs, written = {"zero": 0}, set()
        try:
            insns = list(self.md.disasm(self._code(start, 0x200), start))
        except Exception:
            return None
        for insn in insns:
            m = insn.mnemonic.removeprefix("c.")
            ops = insn.operands
            names = [insn.reg_name(o.reg) if o.type == CS_OP_REG else None for o in ops]
            if self.verbose:
                print(f"    {insn.address:#x}: {insn.mnemonic} {insn.op_str}", file=sys.stderr)

            if m in ("jal", "jalr", "j", "jr", "call", "tail"):  # `c.` prefix already stripped
                tgt = next((o.imm for o in ops if o.type == CS_OP_IMM), None)
                if tgt is not None:
                    tgt = ((insn.address + tgt) if insn.mnemonic.startswith("c.") else tgt) & self.mask
                if tgt is None and names and names[-1]:
                    tgt = regs.get(names[-1])
                is_start = tgt in self.libc_start
                cand = regs.get(self.ARG_REG)
                at_site = until is None or insn.address == until
                if cand is not None and self.is_exec(cand) and cand != self.elf.entry and at_site:
                    what = "__libc_start_main" if is_start else "an internal call"
                    return Found(cand, f"_start trace: main passed at {insn.address:#x} to {what}",
                                 "high" if is_start else "medium")
                if until is not None and insn.address >= until:
                    return None
                if m in ("j", "jr"):
                    return None
                if until is None and (is_start or self.ARG_REG in written):
                    return None      # __libc_start_main never returns: what follows is a different function
                continue
            if m in ("ret", "ebreak", "unimp"):
                if m == "ret" and until is None:
                    continue  # `ret` inside load_gp-style helpers; keep scanning linearly
                return None

            dst = names[0] if ops and ops[0].type == CS_OP_REG and m not in NO_DST_RV else None
            val = None
            if m == "auipc" and len(ops) == 2:
                val = (insn.address + self._upper(ops[1].imm)) & self.mask
            elif m == "lui" and len(ops) == 2:
                val = self._upper(ops[1].imm) & self.mask
            elif m in ("addi", "addiw") and len(ops) == 3 and ops[2].type == CS_OP_IMM:
                b = regs.get(names[1])
                val = (b + ops[2].imm) & self.mask if b is not None else None
            elif m == "li" and len(ops) == 2:
                val = ops[1].imm & self.mask
            elif m == "mv" and len(ops) == 2:
                val = regs.get(names[1])
            elif m in ("ld", "lw", "lwu") and len(ops) == 2 and ops[1].type == CS_OP_MEM:
                base = regs.get(insn.reg_name(ops[1].mem.base))
                if base is not None:
                    val = self._read_ptr((base + ops[1].mem.disp) & self.mask, 8 if m == "ld" else 4)

            if dst and dst != "zero":
                written.add(dst)
                if val is not None:
                    regs[dst] = val
                else:
                    regs.pop(dst, None)
        return None

    def scan(self):
        votes = Counter()
        for lo, hi in self.exec_ranges:
            try:
                data = self.elf.read(lo, min(hi - lo, 32 << 20))
            except Exception:
                continue
            for off in range(0, len(data) - 4, 2):
                try:
                    ins = next(self.md.disasm(data[off:off + 4], lo + off))
                except StopIteration:
                    continue
                if ins.mnemonic not in ("jal", "jalr", "call") or not ins.operands:
                    continue
                op = ins.operands[-1]
                if op.type != CS_OP_IMM or (op.imm & self.mask) not in self.libc_start:
                    continue
                site = lo + off
                for k in range(0x08, 0xA0, 2):
                    r = self.trace(site - k, until=site)
                    if r and r.confidence == "high":
                        votes[r.addr] += 1
        if votes:
            addr, _ = votes.most_common(1)[0]
            return Found(addr, "code scan: call to __libc_start_main", "medium",
                         ["entry point did not lead to main; found by scanning call sites"])
        return None


# ==========================================================================
# PowerPC (32-bit BE, 64-bit LE/BE)
# glibc's ppc _start does NOT pass main in the first argument register. It
# passes r8 = pointer to `struct startup_info { sda_base; main; init; fini; }`
# to __libc_start_main, so main is the *second word* of that struct
# (+4 on ppc32, +8 on ppc64). Verified against qemu execution traces.
#   ppc32:  bcl/mflr get PC ; addis r8,r13,hi ; lwzu r13,lo(r8) ; b __libc_start_main
#   ppc64:  lis/addi build the TOC (r2)  ; ld r8,off(r2)        ; b __libc_start_main
# ELFv1 (ppc64 BE) stores a function *descriptor* there, so one extra deref.
# ==========================================================================
class PpcTracer(ElfHelpers):
    REL_RELATIVE_TYPE = 22  # R_PPC_RELATIVE == R_PPC64_RELATIVE
    ARG_REG = "r8"

    def __init__(self, elf, verbose=False):
        super().__init__(elf, verbose)
        mode = (CS_MODE_64 if self.bits == 64 else CS_MODE_32) | (CS_MODE_BIG_ENDIAN if elf.endian == "big" else 0)
        self.md = Cs(CS_ARCH_PPC, mode)
        self.md.detail = True

    def _main_from_startinfo(self, st):
        if st is None:
            return None
        main = self._read_ptr((st + self.psz) & self.mask, self.psz)
        if main is not None and not self.is_exec(main):      # ELFv1 function descriptor
            main = self._read_ptr(main, self.psz)
        return main if self.is_exec(main) else None

    def trace(self, start, until=None):
        regs, lr, written = {"r12": start}, None, set()      # ELFv2 convention: r12 = global entry address
        try:
            insns = list(self.md.disasm(self._code(start, 0x200), start))
        except Exception:
            return None
        for insn in insns:
            m, ops = insn.mnemonic, insn.operands
            names = [insn.reg_name(o.reg) if o.type == CS_OP_REG else None for o in ops]
            if self.verbose:
                print(f"    {insn.address:#x}: {m} {insn.op_str}", file=sys.stderr)

            # get-PC idiom: a branch-and-link whose target is the next instruction just
            # loads LR with that address (capstone 5 names `bcl 20,31,.+4` "bdnzl", so go by shape)
            if m.startswith("b") and m.endswith("l") and ops and ops[-1].type == CS_OP_IMM \
                    and ops[-1].imm == insn.address + 4:
                lr = insn.address + 4
                continue
            if m in ("b", "bl", "ba", "bla", "bctr", "bctrl"):
                tgt = ops[0].imm if ops and ops[0].type == CS_OP_IMM else None
                cand = self._main_from_startinfo(regs.get("r8"))
                is_start = tgt in self.libc_start
                if cand is not None and cand != self.elf.entry:
                    what = "__libc_start_main" if is_start else "an internal call"
                    return Found(cand, f"_start trace: main read from startup_info passed at {insn.address:#x} to {what}",
                                 "high" if is_start else "medium")
                if m in ("b", "ba", "bctr"):
                    return None
                if is_start or self.ARG_REG in written:
                    return None      # __libc_start_main never returns
                for r in ("r0", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"):
                    regs.pop(r, None)
                continue
            if m in ("blr", "trap"):
                return None

            dst = names[0] if ops and ops[0].type == CS_OP_REG and not m.startswith(NO_DST_PPC) else None
            val = None
            if m == "lis" and len(ops) == 2:
                val = _sext32((ops[1].imm & 0xFFFF) << 16) & self.mask
            elif m == "li" and len(ops) == 2:
                val = _sext16(ops[1].imm) & self.mask
            elif m == "addis" and len(ops) == 3:
                base = 0 if names[1] == "r0" else regs.get(names[1])
                val = (base + _sext32((ops[2].imm & 0xFFFF) << 16)) & self.mask if base is not None else None
            elif m == "addi" and len(ops) == 3:
                base = 0 if names[1] == "r0" else regs.get(names[1])
                val = (base + _sext16(ops[2].imm)) & self.mask if base is not None else None
            elif m == "mr" and len(ops) == 2:
                val = regs.get(names[1])
            elif m == "mflr":
                val = lr
            elif m in ("lwz", "lwzu", "ld", "ldu") and len(ops) == 2 and ops[1].type == CS_OP_MEM:
                bname = insn.reg_name(ops[1].mem.base)
                base = regs.get(bname)
                if base is not None:
                    addr = (base + ops[1].mem.disp) & self.mask
                    val = self._read_ptr(addr, 4 if m.startswith("lwz") else 8)
                    if m.endswith("u"):
                        regs[bname] = addr    # update form writes the effective address back
            if dst:
                written.add(dst)
                if val is not None:
                    regs[dst] = val
                else:
                    regs.pop(dst, None)
        return None

    def scan(self):
        return None   # entry-point trace only; PLT stubs on ppc are not reliably resolvable


# ==========================================================================
# s390x (IBM Z, big-endian)
#   larl %r2, GOT_slot ; lg %r2, 0(%r2)     ; r2 = main (first argument)
#   brasl %r14, __libc_start_main
# ==========================================================================
def _sz_reg(insn, reg):
    """capstone 6 names s390x registers 'r2'; capstone 5 names them '2'."""
    n = insn.reg_name(reg)
    return "r" + n if n and n.isdigit() else n


class S390Tracer(ElfHelpers):
    REL_RELATIVE_TYPE = 8  # R_390_RELATIVE
    ARG_REG = "r2"

    def __init__(self, elf, verbose=False):
        super().__init__(elf, verbose)
        self.md = Cs(CS_ARCH_SYSTEMZ, CS_MODE_BIG_ENDIAN)
        self.md.detail = True

    def _ea(self, insn, mem, regs):
        base = regs.get(_sz_reg(insn, mem.base), None) if mem.base else 0
        idx = regs.get(_sz_reg(insn, mem.index), None) if getattr(mem, "index", 0) else 0
        if base is None or idx is None:
            return None
        return (base + idx + mem.disp) & self.mask

    def trace(self, start, until=None):
        regs, written = {}, set()
        try:
            insns = list(self.md.disasm(self._code(start, 0x200), start))
        except Exception:
            return None
        for insn in insns:
            m, ops = insn.mnemonic, insn.operands
            names = [_sz_reg(insn, o.reg) if o.type == CS_OP_REG else None for o in ops]
            if self.verbose:
                print(f"    {insn.address:#x}: {m} {insn.op_str}", file=sys.stderr)

            if m in ("brasl", "bras", "basr", "balr", "jg", "j", "brcl", "br"):
                tgt = next((o.imm & self.mask for o in ops if o.type == CS_OP_IMM), None)
                cand = regs.get("r2")
                is_start = tgt in self.libc_start
                if cand is not None and self.is_exec(cand) and cand != self.elf.entry:
                    what = "__libc_start_main" if is_start else "an internal call"
                    return Found(cand, f"_start trace: main passed at {insn.address:#x} to {what}",
                                 "high" if is_start else "medium")
                if m in ("jg", "j", "brcl", "br"):
                    return None
                if is_start or self.ARG_REG in written:
                    return None      # __libc_start_main never returns
                for r in ("r0", "r1", "r2", "r3", "r4", "r5"):
                    regs.pop(r, None)
                continue

            dst = names[0] if ops and ops[0].type == CS_OP_REG and not m.startswith(NO_DST_S390) else None
            val = None
            if m == "larl" and len(ops) == 2 and ops[1].type == CS_OP_IMM:
                val = ops[1].imm & self.mask
            elif m in ("lghi", "lhi", "lgfi", "llilf", "llihf") and len(ops) == 2 and ops[1].type == CS_OP_IMM:
                val = ops[1].imm & self.mask
            elif m in ("lgr", "lr") and len(ops) == 2:
                val = regs.get(names[1])
            elif m in ("la", "lay") and len(ops) == 2 and ops[1].type == CS_OP_MEM:
                val = self._ea(insn, ops[1].mem, regs)
            elif m in ("lg", "lgf", "l") and len(ops) == 2 and ops[1].type == CS_OP_MEM:
                slot = self._ea(insn, ops[1].mem, regs)
                val = self._read_ptr(slot, 8 if m == "lg" else 4) if slot is not None else None
            elif m in ("lgrl", "lrl") and len(ops) == 2 and ops[1].type == CS_OP_IMM:
                val = self._read_ptr(ops[1].imm & self.mask, 8 if m == "lgrl" else 4)
            if dst:
                written.add(dst)
                if val is not None:
                    regs[dst] = val
                else:
                    regs.pop(dst, None)
        return None

    def scan(self):
        return None


def arch_key(elf):
    """pwntools reports EM_S390 as 'em_s390'; give it a proper name."""
    if elf.arch == "em_s390" or elf.header.e_machine == "EM_S390":
        return "s390x" if elf.bits == 64 else "s390"
    return elf.arch


SUPPORTED_ARCHS = ("amd64", "i386", "arm", "aarch64", "mips", "mips64", "powerpc", "powerpc64", "s390x") + (("riscv32", "riscv64") if HAVE_RISCV else ())


def locate(elf, verbose=False):
    sym = elf.symbols.get("main") or None
    sym_thumb = False
    if arch_key(elf) == "arm" and sym:
        sym_thumb, sym = bool(sym & 1), sym & ~1
    found = None
    tracer_cls = {
        "amd64": X86Tracer, "i386": X86Tracer,
        "arm": ArmTracer, "aarch64": Arm64Tracer,
        "mips": MipsTracer, "mips64": MipsTracer,
        "powerpc": PpcTracer, "powerpc64": PpcTracer, "s390x": S390Tracer,
        **({"riscv32": RiscvTracer, "riscv64": RiscvTracer} if HAVE_RISCV else {}),
    }.get(arch_key(elf))
    if tracer_cls:
        try:
            tr = tracer_cls(elf, verbose)
            found = tr.trace(elf.entry) or tr.scan()
        except Exception as e:      # e.g. this capstone build lacks the ISA: fall back to symbols
            found, tr = None, None
            if verbose:
                print(f"[!] {tracer_cls.__name__} failed: {type(e).__name__}: {e}", file=sys.stderr)
        if found and tracer_cls is ArmTracer:
            found.thumb = found.thumb or bool(found.addr & 1) or tr.thumb
            found.addr &= ~1
            tr._set_mode(found.thumb)
        if found:
            branch, nops = {
                X86Tracer: (("jmp",), ()),
                ArmTracer: (("b",), ("nop",)),
                Arm64Tracer: (("b",), ("nop",)),
                MipsTracer: (("j",), ("nop",)),
                PpcTracer: ((), ()), S390Tracer: ((), ()),
                **({RiscvTracer: (("j", "c.j"), ("nop", "c.nop"))} if HAVE_RISCV else {}),
            }[tracer_cls]
            try:
                new_addr = chase_trampoline(elf, tr.md, found.addr, branch, nops, tr.is_exec, tr.mask)
            except Exception:
                new_addr = found.addr
            if new_addr != found.addr:
                found.addr = new_addr
                found.notes.append(f"followed a trampoline/wrapper to the real function at {new_addr:#x}")
    if found:
        if sym == found.addr:
            found.notes.append("agrees with symbol table `main`")
        elif sym:
            found.notes.append(f"WARNING: symtab `main` = {sym:#x} disagrees (decoy symbol?)")
    elif sym:
        found = Found(sym, "symbol table (`main`)", "high", thumb=sym_thumb)
    elif elf.symbols.get("main.main"):
        found = Found(elf.symbols["main.main"], "symbol `main.main` (Go)", "low",
                      ["Go user main; the C-level main is a runtime shim"])
    return found


def section_of(elf, addr):
    for s in elf.iter_sections():
        h = s.header
        if h.sh_flags & 2 and h.sh_addr <= addr < h.sh_addr + h.sh_size:
            return s.name
    return None


def preview(elf, addr, n, thumb=False):
    if n <= 0:
        return
    cfg = {
        "amd64": (CS_ARCH_X86, CS_MODE_64), "i386": (CS_ARCH_X86, CS_MODE_32),
        "arm": (CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM),
        "aarch64": (CS_ARCH_AARCH64, 0),
        **({"riscv64": (CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC),
            "riscv32": (CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)} if HAVE_RISCV else {}),
        "mips": (CS_ARCH_MIPS, CS_MODE_MIPS32 | (CS_MODE_BIG_ENDIAN if elf.endian == "big" else 0)),
        "mips64": (CS_ARCH_MIPS, CS_MODE_MIPS64 | (CS_MODE_BIG_ENDIAN if elf.endian == "big" else 0)),
        "powerpc": (CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN),
        "powerpc64": (CS_ARCH_PPC, CS_MODE_64 | (CS_MODE_BIG_ENDIAN if elf.endian == "big" else 0)),
        **({"s390x": (CS_ARCH_SYSTEMZ, CS_MODE_BIG_ENDIAN)} if CS_ARCH_SYSTEMZ is not None else {}),
    }.get(arch_key(elf))
    if not cfg:
        return
    try:
        md = Cs(*cfg)
        for i in md.disasm(elf.read(addr, 16 * n), addr, n):
            print(f"    {C}{i.address:#x}{RS}: {i.mnemonic} {i.op_str}")
    except Exception:
        pass


def gettingBasicInfo(elf):
    print(f"{C}Arch              : {RS}{elf.arch}")
    print(f"{C}Bits              : {RS}{elf.bits}")
    print(f"{C}PIE               : {RS}{elf.pie}")
    print(f"{C}Canary            : {RS}{elf.canary}")
    print(f"{C}NX                : {RS}{elf.nx}")
    print(f"{C}RELRO             : {RS}{elf.relro}")
    print(f"{R}Stripped          : {R}{elf.stripped}{RS}")
    print(f"{C}Statically linked : {RS}{elf.statically_linked}\n")


def qemu_user_name(elf):
    """Name of the qemu-user binary for this ELF (qemu-<name>)."""
    key, le = arch_key(elf), elf.endian == "little"
    table = {"amd64": "x86_64", "i386": "i386", "arm": "arm", "aarch64": "aarch64",
             "riscv32": "riscv32", "riscv64": "riscv64", "s390x": "s390x", "s390": "s390x",
             "mips": "mipsel" if le else "mips", "mips64": "mips64el" if le else "mips64",
             "powerpc": "ppc", "powerpc64": "ppc64le" if le else "ppc64",
             "sparc": "sparc", "sparc64": "sparc64"}
    return table.get(key, key)


def cross_debug_hint(elf_path, elf, addr, extra_args):
    """Native gdb can't run a foreign-arch binary: print the qemu-user +
    gdb-multiarch recipe, and say what is missing if a tool isn't installed."""
    q = qemu_user_name(elf)
    qemu = shutil.which(f"qemu-{q}") or shutil.which(f"qemu-{q}-static")
    gdbm = shutil.which("gdb-multiarch")
    bp = addr | 1 if (arch_key(elf) == "arm" and elf.entry & 1) else addr   # Thumb: odd address
    path = os.path.abspath(elf_path)
    sysroot = ""
    try:
        if elf.linker:   # dynamically linked: qemu needs a matching sysroot to find ld.so/libc
            sysroot = " -L /usr/<triplet>   # e.g. /usr/arm-linux-gnueabihf (apt: libc6-<arch>-cross)"
    except Exception:
        pass
    run = f"{qemu or 'qemu-' + q} -g 1234{' -L /usr/<triplet>' if sysroot else ''} {path} {' '.join(extra_args or [])}".strip()
    dbg = f"gdb-multiarch -q {path} -ex 'target remote :1234' -ex 'break *{bp:#x}' -ex continue"
    print(f"{Y}[!] {arch_key(elf)} binary: native gdb can't run it. Use qemu-user + gdb-multiarch:{RS}")
    print(f"    1) {run}\n    2) {dbg}")
    if elf.pie:
        print("    (PIE: qemu loads it at a base address; run `info proc mappings` in gdb and add the base to the offset.)")
    missing = [n for n, ok in ((f"qemu-user (qemu-{q})", qemu), ("gdb-multiarch", gdbm)) if not ok]
    if missing:
        print(f"{R}    missing: {', '.join(missing)}{RS}  ->  apt install qemu-user gdb-multiarch")
    return 0


def spawn_gdb(elf_path, elf, addr, extra_args=None):
    """Launch gdb on elf_path with a breakpoint at addr (file-offset based, so
    it's correct whether or not the binary is PIE) and let it run."""
    if arch_key(elf) not in ("amd64", "i386"):
        return cross_debug_hint(elf_path, elf, addr, extra_args)
    gdb_bin = shutil.which("gdb")
    if not gdb_bin:
        print(f"{R}[-] gdb not found on PATH{RS}")
        return 1

    try:
        file_off = elf.vaddr_to_offset(addr)
    except Exception:
        file_off = None

    # gdb disables ASLR for the debuggee by default, and always loads a PIE
    # binary's first PT_LOAD at 0x555555554000 (64-bit) / 0x56555000 (32-bit)
    # in that case, so the runtime address is predictable without needing
    # pwndbg's $rebase(). If pwndbg IS loaded, prefer it (works even if the
    # user later runs "set disable-randomization off").
    if elf.pie and file_off is not None:
        default_base = 0x555555554000 if elf.bits == 64 else 0x56555000
        static_guess = hex((default_base + file_off) & ((1 << elf.bits) - 1))
        # Two independent -ex commands, not one multi-line python block:
        # gdb keeps processing the next -ex even if one errors out, so if
        # pwndbg isn't loaded (`$rebase` undefined) that break just fails
        # and the static-address break below still gets set.
        breaks = [f"break *$rebase({hex(file_off)})", f"break *{static_guess}"]
    else:
        breaks = [f"break *{hex(addr)}"]

    print(f"{C}[*] spawning gdb, breakpoint at main ({hex(addr)}"
          f"{', PIE-relative' if elf.pie else ''}){RS}")
    # NOTE: gdb's --args swallows every token after it as the debuggee's
    # argv, so -ex flags must come first; the debuggee's args are set via
    # `set args`, not by placing them after --args.
    cmd = [gdb_bin, "-q", os.path.abspath(elf_path)]
    for c in breaks:
        cmd += ["-ex", c]
    if extra_args:
        cmd += ["-ex", "set args " + " ".join(extra_args)]
    cmd += ["-ex", "run"]
    # Hand the terminal straight to gdb (no Python parent in between), with the
    # cursor explicitly re-enabled in case anything hid it.
    if sys.stdout.isatty():
        sys.stdout.write("\x1b[?25h")
    sys.stdout.flush()
    sys.stderr.flush()
    os.execvp(cmd[0], cmd)


def main():
    ap = argparse.ArgumentParser(description="Find main() in an ELF binary, stripped or not.")
    ap.add_argument("name", help="ELF file")
    ap.add_argument("-q", "--quiet", action="store_true", help="print only the address (for scripting)")
    ap.add_argument("-n", "--insns", type=int, default=6, help="instructions to preview (default 6)")
    ap.add_argument("-i", "--info", action="store_true", help="also print basic binary info")
    ap.add_argument("-v", "--verbose", action="store_true", help="show the _start trace on stderr")
    ap.add_argument("-b", "--break-main", action="store_true", dest="brk",
                     help="spawn gdb with a breakpoint at main and run it, no prompt")
    ap.add_argument("-y", "--yes", action="store_true",
                     help="answer yes to the 'break at main?' prompt (same effect as -b)")
    ap.add_argument("--args", nargs=argparse.REMAINDER, default=[],
                     help="remaining args are passed to the debuggee when spawning gdb")
    args = ap.parse_args()

    try:
        elf = ELF(args.name, checksec=False)
    except Exception as e:
        sys.exit(f"[-] cannot load {args.name}: {e}")

    if args.info and not args.quiet:
        gettingBasicInfo(elf)

    f = locate(elf, args.verbose)
    if not f:
        if not args.quiet:
            why = "" if arch_key(elf) in SUPPORTED_ARCHS else f" (no start-up tracer for arch '{arch_key(elf)}' yet; only symbols were checked)"
            print(f"{R}[-] could not locate main{RS}{why}")
        sys.exit(1)

    if args.quiet:
        print(hex(f.addr))
        if args.brk or args.yes:          # -q only silences the report, not an explicit -b/-y
            sys.exit(spawn_gdb(args.name, elf, f.addr, args.args))
        return

    try:
        off = hex(elf.vaddr_to_offset(f.addr))
    except Exception:
        off = "?"
    conf = {"high": G, "medium": Y, "low": R}[f.confidence]
    print(f"{G}[+] main{RS}       : {G}{f.addr:#x}{RS}  (file offset {off}, section {section_of(elf, f.addr) or '?'})")
    print(f"{C}    method{RS}     : {f.method}")
    print(f"{C}    confidence{RS} : {conf}{f.confidence}{RS}")
    for n in f.notes:
        print(f"{Y}    note{RS}       : {n}")
    if elf.pie:
        print(f"{C}    PIE{RS}        : address is relative to the load base")
    if f.thumb:
        print(f"{C}    ISA{RS}        : Thumb (address shown without the Thumb bit; use {f.addr | 1:#x} for interworking)")
    preview(elf, f.addr, args.insns, f.thumb)

    do_break = args.brk
    if not do_break and not args.yes and sys.stdin.isatty():
        try:
            ans = input(f"\n{Y}[?] spawn gdb with a breakpoint at main? [y/N] {RS}").strip().lower()
        except EOFError:
            ans = ""
        do_break = ans in ("y", "yes")
    elif not do_break and args.yes:
        do_break = True

    if do_break:
        sys.exit(spawn_gdb(args.name, elf, f.addr, args.args))


if __name__ == "__main__":
    main()