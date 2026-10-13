# Oberview
Find main() -- stripped or not. (>.<)

## Usage :: elf Binaries
```python
    usage: findmain.py [-h] [-q] [-n INSNS] [-i] [-v] [-b] [-y] [--args ...] name


    positional arguments:
    name               ELF file

    options:
    -h, --help         show this help message and exit
    -q, --quiet        print only the address (for scripting)
    -n, --insns INSNS  instructions to preview (default 6)
    -i, --info         also print basic binary info
    -v, --verbose      show the _start trace on stderr
    -b, --break-main   spawn gdb with a breakpoint at main and run it, no prompt
    -y, --yes          answer yes to the 'break at main?' prompt (same effect as -b)
    --args ...         remaining args are passed to the debuggee when spawning gdb
    
```
## Usage :: Windows Executables exe.

```python
    usage: findmain.py [-h] [-q] [-n INSNS] [-i] [-v] [-b] [-y] [--args ...] name

    Find main() in a Windows PE binary (32/64-bit), stripped or not.

    positional arguments:
    name               PE (.exe) file

    options:
    -h, --help         show this help message and exit
    -q, --quiet        print only the address (for scripting)
    -n, --insns INSNS  instructions to preview (default 6)
    -i, --info         also print basic binary info
    -v, --verbose      show the startup trace on stderr
    -b, --break-main   run under winedbg with a breakpoint at main, no prompt
    -y, --yes          answer yes to the 'run under winedbg?' prompt (same effect as -b)
    --args ...         remaining args are passed to the debuggee under winedbg

```