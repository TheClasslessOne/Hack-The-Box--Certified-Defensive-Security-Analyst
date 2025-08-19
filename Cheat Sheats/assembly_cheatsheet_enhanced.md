# 🧩 Intro to Assembly Language — Enhanced Cheat Sheet

This reference is designed to be more structured and in-depth. It covers **registers, assembly instructions, GDB debugging, calling conventions, and shellcoding**.

---

# 📑 Table of Contents

1. [Registers](#registers)
2. [Assembly & Disassembly Tools](#assembly--disassembly-tools)
3. [GDB Debugging](#gdb-debugging)
4. [Assembly Instructions](#assembly-instructions)
   - Data Movement
   - Arithmetic (Unary & Binary)
   - Bitwise Operations
   - Loops & Branching
   - Stack
   - Functions
5. [Functions & Conventions](#functions--conventions)
   - Syscall Convention
   - Function Calling Convention
6. [Shellcoding](#shellcoding)
   - Tools & Commands
   - Requirements

---

# 🏗️ Registers

| Purpose | 64-bit Register | 8-bit Register |
|---------|----------------|----------------|
| **Data / Arguments** |
| Syscall number / Return value | `rax` | `al` |
| Callee-saved general register | `rbx` | `bl` |
| 1st arg | `rdi` | `dil` |
| 2nd arg | `rsi` | `sil` |
| 3rd arg | `rdx` | `dl` |
| 4th arg (loop counter) | `rcx` | `cl` |
| 5th arg | `r8` | `r8b` |
| 6th arg | `r9` | `r9b` |
| **Pointer Registers** |
| Base pointer (stack frame) | `rbp` | `bpl` |
| Stack pointer (top of stack) | `rsp` | `spl` |
| Instruction pointer | `rip` | *N/A* |

---

# ⚙️ Assembly & Disassembly Tools

| Command | Description |
|---------|-------------|
| `nasm -f elf64 hello.s` | Assemble code |
| `ld -o hello hello.o` | Link object file |
| `ld -o fib fib.o -lc --dynamic-linker /lib64/ld-linux-x86-64.so.2` | Link with libc |
| `objdump -M intel -d hello` | Disassemble `.text` |
| `objdump -M intel --no-show-raw-insn --no-addresses -d hello` | Disassemble without raw bytes |
| `objdump -sj .data hello` | View `.data` section |

---

# 🐞 GDB Debugging

| Command | Description |
|---------|-------------|
| `gdb -q ./hello` | Start GDB |
| `info functions` | List functions |
| `info variables` | List variables |
| `info registers` | Show register state |
| `disas _start` | Disassemble function |
| `b _start` | Break at function |
| `b *0x401000` | Break at address |
| `r` | Run program |
| `x/4xg $rip` | Examine 4 values at RIP |
| `si` | Step one instruction |
| `s` | Step one line (source) |
| `ni` | Step into function |
| `c` | Continue |
| `patch string 0x402000 "Patched!\n"` | Patch memory |
| `set $rdx=0x9` | Change register value |

---

# 🧮 Assembly Instructions

## Data Movement
- `mov rax, 1` → set `rax = 1`
- `lea rax, [rsp+5]` → load address into `rax`
- `xchg rax, rbx` → swap `rax` and `rbx`

## Unary Arithmetic
- `inc rax` → increment (`rax++`)
- `dec rax` → decrement (`rax--`)

## Binary Arithmetic
- `add rax, rbx` → `rax = rax + rbx`
- `sub rax, rbx` → `rax = rax - rbx`
- `imul rax, rbx` → `rax = rax * rbx`

## Bitwise
- `not rax` → invert bits
- `and rax, rbx` → bitwise AND
- `or rax, rbx` → bitwise OR
- `xor rax, rbx` → bitwise XOR

## Loops & Branching
- `mov rcx, 3` → set loop counter
- `loop label` → decrement `rcx` and jump if not zero
- `jmp label` → unconditional jump
- `cmp rax, rbx` → set flags (`rax - rbx`)
- Conditional jumps: `jz`, `jnz`, `jg`, `jl`, `jge`, `jle`, `js`, `jns`

## Stack
- `push rax` → push onto stack
- `pop rax` → pop into register

## Functions
- `call func` → push `rip`, jump to func
- `ret` → pop return address into `rip`

---

# 🛠️ Functions & Conventions

### Syscall Calling Convention
1. Save caller-saved registers
2. Place syscall number in `rax`
3. Place arguments in `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`
4. Execute `syscall`

Example (write syscall):
```asm
mov rax, 1        ; syscall: write
mov rdi, 1        ; fd: stdout
mov rsi, msg      ; buffer
mov rdx, 13       ; length
syscall
```

### Function Calling Convention (System V AMD64)
1. Save caller-saved registers (`rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8–r11`)
2. Pass args in registers (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`)
3. Ensure stack alignment (16 bytes)
4. Return value in `rax`

---

# 💣 Shellcoding

## Tools & Commands
| Command | Description |
|---------|-------------|
| `pwn asm 'push rax' -c amd64` | Instruction → shellcode |
| `pwn disasm '50' -c amd64` | Shellcode → instruction |
| `python3 shellcoder.py helloworld` | Extract shellcode |
| `python3 loader.py '4831..0f05'` | Run shellcode |
| `python assembler.py '4831..0f05'` | Assemble shellcode |

### Shellcraft
| Command | Description |
|---------|-------------|
| `pwn shellcraft -l amd64.linux` | List syscalls |
| `pwn shellcraft amd64.linux.sh` | Generate `/bin/sh` shellcode |
| `pwn shellcraft amd64.linux.sh -r` | Run shellcode |

### Msfvenom
| Command | Description |
|---------|-------------|
| `msfvenom -l payloads | grep linux/x64` | List payloads |
| `msfvenom -p linux/x64/exec CMD='sh' -f hex` | Generate shellcode |
| `msfvenom -p linux/x64/exec CMD='sh' -f hex -e x64/xor` | Generate encoded shellcode |

---

## Shellcoding Requirements
1. No variables
2. No direct memory references
3. No NULL bytes (`0x00`)

---
