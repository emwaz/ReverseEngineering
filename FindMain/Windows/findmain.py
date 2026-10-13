#!/usr/bin/env python3
"""
findmain - locate main() in a Windows PE binary (32-bit or 64-bit), stripped
or not. ELF is intentionally not handled by this build.

A release PE carries no symbol table (debug info lives in a separate, usually
absent, .pdb) and there's no __libc_start_main-style anchor to lock onto.
Instead, every normal C/C++ entry point calls the user's `main` and then, on
the same path, calls one of the process-exit imports (exit, _cexit,
ExitProcess, ...). This script walks the direct-call/jmp graph from the PE
entry point - forking at conditional branches, bounded by a depth and
instruction budget - and, on every path that reaches an exit-family *import*
call, reports the most recent direct call to a *non-import* address seen on
that path. That's `main`.

  MinGW example (verified against real binaries, x86 and x64):
    _mainCRTStartup:  jmp __tmainCRTStartup            ; tail jump, x86
    mainCRTStartup:   call __tmainCRTStartup           ; call, x64
    __tmainCRTStartup:  ... call __main ... call main ... call exit

MSVC-built binaries follow the same shape (invoke_main -> main -> exit) but
were not available to test against; only MinGW output has been verified.

Requires the `pefile` package: pip install pefile --break-system-packages

Debugging (-b/-y): since this is meant to run under Wine, breakpoints are
set via `winedbg --gdb`, not native gdb (a PE binary can't run under native
gdb at all). winedbg's --gdb mode always drives its own interactive gdb
session rather than accepting a bare gdbserver connection to script - trying
to script it externally hits a real assertion crash in the gdbproxy of the
Wine version this was tested against - so -b/-y hands you into that real,
working session and prints the two commands to type once it stops at the
initial DbgBreakPoint. This has been verified end-to-end: Wine's own gdb
independently resolves the reported address as `main` by name.

Go/Rust runtimes are intentionally not handled.
"""
import argparse
import os
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field

try:
    import pefile
except ImportError:
    sys.exit("[-] the 'pefile' package isn't installed.\n    pip install pefile --break-system-packages")

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_OP_IMM, CS_OP_MEM

from colorama import Fore, Style, init
init()
G = Fore.GREEN + Style.BRIGHT
R = Fore.RED + Style.BRIGHT
Y = Fore.YELLOW + Style.BRIGHT
C = Fore.CYAN + Style.BRIGHT
RS = Style.RESET_ALL


@dataclass
class Found:
    addr: int
    method: str
    confidence: str
    notes: list = field(default_factory=list)


EXIT_IMPORTS = (  # ordered by how strongly they indicate "this is the real exit call"
    "exit", "_exit", "_Exit", "quick_exit", "ExitProcess",
    "_cexit", "_c_exit", "_o_exit", "_amsg_exit", "RtlExitUserProcess",
)


class PEHelpers:
    def __init__(self, pe, verbose=False):
        self.pe, self.verbose = pe, verbose
        self.bits = 64 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 32
        self.mask = (1 << self.bits) - 1
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.entry = self.base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.exec_ranges = [
            (self.base + s.VirtualAddress, self.base + s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData))
            for s in pe.sections if s.Characteristics & 0x20000000        # IMAGE_SCN_MEM_EXECUTE
        ]
        self.imports = {}          # IAT slot VA -> "dll!Name"
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode(errors="replace") if isinstance(entry.dll, bytes) else str(entry.dll)
            for imp in entry.imports:
                if imp.address is None:
                    continue
                name = imp.name.decode(errors="replace") if imp.name else f"ordinal_{imp.ordinal}"
                self.imports[imp.address] = f"{dll}!{name}"
        self._thunk_cache = {}

    def is_exec(self, a):
        return a is not None and any(lo <= a < hi for lo, hi in self.exec_ranges)

    def _code(self, addr, n=0x200):
        while n > 0:
            try:
                return self.pe.get_data(addr - self.base, n)
            except Exception:
                n //= 2
        return b""

    def import_name(self, slot):
        return self.imports.get(slot)

    def _mem_slot(self, insn, mem):
        """Resolve a memory operand with no base/index register (x86 absolute
        disp) or RIP-relative (x64) to the absolute address it references."""
        if getattr(mem, "index", 0):
            return None
        if mem.base == 0:
            return mem.disp & self.mask
        if insn.reg_name(mem.base) == "rip":
            return (insn.address + insn.size + mem.disp) & self.mask
        return None

    def resolve_branch(self, insn, md):
        """-> ('import', name) | ('code', addr) | (None, None) for the target
        of a call/jmp: a direct immediate, a fixed-address memory operand
        (IAT-style), or a thunk `jmp [iat_slot]` sitting at a direct address."""
        op = insn.operands[0] if insn.operands else None
        if op is None:
            return None, None
        if op.type == CS_OP_IMM:
            tgt = op.imm & self.mask
            name = self._thunk_import(tgt, md)
            return ("import", name) if name else ("code", tgt)
        if op.type == CS_OP_MEM:
            slot = self._mem_slot(insn, op.mem)
            if slot is None:
                return None, None
            name = self.import_name(slot)
            return ("import", name) if name else (None, None)
        return None, None

    def _thunk_import(self, addr, md):
        """True if `addr` is a single-instruction `jmp [iat_slot]` stub."""
        if addr in self._thunk_cache:
            return self._thunk_cache[addr]
        name = None
        if self.is_exec(addr):
            try:
                code = self._code(addr, 8)
                ins = next(md.disasm(code, addr))
                if ins.mnemonic == "jmp" and ins.operands and ins.operands[0].type == CS_OP_MEM:
                    slot = self._mem_slot(ins, ins.operands[0].mem)
                    if slot is not None:
                        name = self.import_name(slot)
            except Exception:
                pass
        self._thunk_cache[addr] = name
        return name


class PeTracer(PEHelpers):
    def __init__(self, pe, verbose=False):
        super().__init__(pe, verbose)
        self.md = Cs(CS_ARCH_X86, CS_MODE_64 if self.bits == 64 else CS_MODE_32)
        self.md.detail = True

    def trace(self, start=None, max_depth=4, budget=30000):
        start = self.entry if start is None else start
        work = [(start, None, 0)]
        visits = Counter()
        candidates = []  # (anchor_name, depth, addr)
        left = budget
        while work and left > 0:
            addr, last_target, depth = work.pop()
            addr, last_target, left, hit = self._walk(addr, last_target, depth, max_depth, work, visits, left)
            if hit:
                candidates.append(hit)
        if not candidates:
            return None
        pri = {n: i for i, n in enumerate(EXIT_IMPORTS)}
        candidates.sort(key=lambda c: (pri.get(c[0], 99), c[1]))
        best_anchor, best_depth, _ = candidates[0]
        votes = Counter(c[2] for c in candidates if c[0] == best_anchor and c[1] == best_depth)
        addr = votes.most_common(1)[0][0]
        return Found(addr, f"startup trace: last local call before `{best_anchor}`", "high",
                     [f"reached via the exit-family import {best_anchor!r}"])

    def _walk(self, addr, last_target, depth, max_depth, work, visits, left):
        while left > 0:
            code = self._code(addr)
            if not code:
                return addr, last_target, left, None
            next_addr = None
            for insn in self.md.disasm(code, addr):
                left -= 1
                visits[insn.address] += 1
                if left <= 0 or visits[insn.address] > 2:
                    return addr, last_target, left, None
                m, ops = insn.mnemonic, insn.operands
                if self.verbose:
                    print(f"    [{depth}] {insn.address:#x}: {m} {insn.op_str}", file=sys.stderr)

                if m and m[0] == "j" and m != "jmp" and ops and ops[0].type == CS_OP_IMM:
                    work.append((ops[0].imm & self.mask, last_target, depth))
                    continue

                if m == "jmp":
                    kind, tgt = self.resolve_branch(insn, self.md)
                    if kind == "import":
                        if tgt and any(tgt.split("!")[-1].lower().startswith(n.lower()) for n in EXIT_IMPORTS) and last_target is not None:
                            return addr, last_target, left, (self._exit_name(tgt), depth, last_target)
                        return addr, last_target, left, None
                    if kind == "code" and self.is_exec(tgt):
                        next_addr = tgt
                        break
                    return addr, last_target, left, None

                if m == "call":
                    kind, tgt = self.resolve_branch(insn, self.md)
                    if kind == "import":
                        if tgt and any(tgt.split("!")[-1].lower().startswith(n.lower()) for n in EXIT_IMPORTS) and last_target is not None:
                            return addr, last_target, left, (self._exit_name(tgt), depth, last_target)
                        continue  # ordinary library call, keep going
                    if kind == "code" and self.is_exec(tgt) and tgt != self.entry:
                        last_target = tgt
                        if depth < max_depth:
                            work.append((tgt, last_target, depth + 1))
                        continue
                    continue  # unresolved indirect call: skip past it

                if m in ("ret", "retn", "int3", "ud2", "hlt"):
                    return addr, last_target, left, None
            if next_addr is None:
                return addr, last_target, left, None
            addr = next_addr
        return addr, last_target, left, None

    @staticmethod
    def _exit_name(dllbang):
        n = dllbang.split("!")[-1]
        for want in EXIT_IMPORTS:
            if n.lower().startswith(want.lower()):
                return want
        return n


def locate(pe, verbose=False):
    tr = PeTracer(pe, verbose)
    found = tr.trace()
    if not found:
        found = Found(tr.entry, "PE entry point (no `main` pattern recognized)", "low",
                      ["Could not confirm this via an exit-family call; showing raw entry point."])
    return found, tr


def section_of(pe, addr):
    for sec in pe.sections:
        lo = pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
        hi = lo + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
        if lo <= addr < hi:
            return sec.Name.rstrip(b"\x00").decode(errors="replace")
    return None


def preview(tr, addr, n):
    if n <= 0:
        return
    try:
        for i in tr.md.disasm(tr._code(addr, 16 * n), addr, n):
            print(f"    {C}{i.address:#x}{RS}: {i.mnemonic} {i.op_str}")
    except Exception:
        pass


def basic_info(pe, tr):
    print(f"{C}Arch              : {RS}{'x86-64' if tr.bits == 64 else 'x86'}")
    print(f"{C}Bits              : {RS}{tr.bits}")
    dynbase = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40)   # DYNAMIC_BASE (ASLR)
    nx = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x100)       # NX_COMPAT
    print(f"{C}ASLR (DYNAMICBASE): {RS}{dynbase}")
    print(f"{C}NX (NX_COMPAT)    : {RS}{nx}")
    print(f"{R}Subsystem         : {R}{pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, pe.OPTIONAL_HEADER.Subsystem)}{RS}")
    print()


def wine_debug(exe_path, addr, extra_args):
    """`winedbg --gdb <exe>` launches wine, attaches, and drives its OWN
    embedded gdb session interactively (it is not a bare gdbserver you can
    pre-script with -ex flags, and its --no-start+external-gdb combo hits a
    real assertion crash in winedbg's gdbproxy in the version this was
    tested against). So: hand the user straight into that real, working
    session and tell them the two commands to type. Verified end-to-end:
    winedbg's own gdb independently resolves the reported address as
    `main` by name once the breakpoint is set.
    """
    winedbg = shutil.which("winedbg")
    if not winedbg:
        print(f"{Y}[!] winedbg not found. Install the 'wine' package, or run manually:{RS}")
        print(f"    winedbg --gdb {exe_path}")
        print(f"    (once it stops at DbgBreakPoint) break *{addr:#x}")
        print(f"    continue")
        return 1
    print(f"{C}[*] starting: winedbg --gdb {exe_path}{RS}")
    print(f"{Y}    winedbg stops at DbgBreakPoint first (that's normal). At the Wine-gdb> prompt, type:{RS}")
    print(f"      break *{addr:#x}")
    print(f"      continue")
    sys.stdout.write("\x1b[?25h")  # make sure the cursor is visible
    sys.stdout.flush()
    os.execvp(winedbg, [winedbg, "--gdb", os.path.abspath(exe_path)] + (extra_args or []))


def main():
    ap = argparse.ArgumentParser(description="Find main() in a Windows PE binary (32/64-bit), stripped or not.")
    ap.add_argument("name", help="PE (.exe) file")
    ap.add_argument("-q", "--quiet", action="store_true", help="print only the address (for scripting)")
    ap.add_argument("-n", "--insns", type=int, default=6, help="instructions to preview (default 6)")
    ap.add_argument("-i", "--info", action="store_true", help="also print basic binary info")
    ap.add_argument("-v", "--verbose", action="store_true", help="show the startup trace on stderr")
    ap.add_argument("-b", "--break-main", action="store_true", dest="brk",
                     help="run under winedbg with a breakpoint at main, no prompt")
    ap.add_argument("-y", "--yes", action="store_true",
                     help="answer yes to the 'run under winedbg?' prompt (same effect as -b)")
    ap.add_argument("--args", nargs=argparse.REMAINDER, default=[],
                     help="remaining args are passed to the debuggee under winedbg")
    args = ap.parse_args()

    try:
        with open(args.name, "rb") as fh:
            magic = fh.read(2)
    except OSError as e:
        sys.exit(f"[-] cannot open {args.name}: {e}")
    if magic != b"MZ":
        sys.exit(f"[-] {args.name}: not a PE file (this build only handles Windows PE, not ELF)")

    try:
        pe = pefile.PE(args.name)
    except Exception as e:
        sys.exit(f"[-] cannot load {args.name}: {e}")
    if pe.PE_TYPE not in (pefile.OPTIONAL_HEADER_MAGIC_PE, pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS):
        sys.exit(f"[-] {args.name}: unrecognized PE optional-header type")

    f, tr = locate(pe, args.verbose)

    if args.info and not args.quiet:
        basic_info(pe, tr)

    if args.quiet:
        print(hex(f.addr))
        if args.brk or args.yes:
            sys.exit(wine_debug(args.name, f.addr, args.args))
        return

    conf = {"high": G, "medium": Y, "low": R}[f.confidence]
    off = f.addr - tr.base
    print(f"{G}[+] main{RS}       : {G}{f.addr:#x}{RS}  (RVA {hex(off)}, section {section_of(pe, f.addr) or '?'})")
    print(f"{C}    method{RS}     : {f.method}")
    print(f"{C}    confidence{RS} : {conf}{f.confidence}{RS}")
    for n in f.notes:
        print(f"{Y}    note{RS}       : {n}")
    print(f"{C}    ImageBase{RS}  : {tr.base:#x}  (address above is an absolute VA at this default base)")
    preview(tr, f.addr, args.insns)

    do_break = args.brk
    if not do_break and not args.yes and sys.stdin.isatty():
        try:
            ans = input(f"\n{Y}[?] run under winedbg with a breakpoint at main? [y/N] {RS}").strip().lower()
        except EOFError:
            ans = ""
        do_break = ans in ("y", "yes")
    elif not do_break and args.yes:
        do_break = True
    if do_break:
        sys.exit(wine_debug(args.name, f.addr, args.args))


if __name__ == "__main__":
    main()