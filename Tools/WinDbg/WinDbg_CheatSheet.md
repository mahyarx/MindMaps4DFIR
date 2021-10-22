# WinDbg

## Breakpoints

### bp <Addr>: regular breakpoint

bp deadbeef
bp kernel32!CreateFileA
bp Module!Class::Method

### bp <Addr> <Num>: break at the Nth hit

bp kernel32!CreateFileA 5

### bu <Addr>: unresolved breakpoint

module not loaded yet

### bm module!<Regex>: symbols breakpoint

bm kernel32!Process*

### ba <Access> <Size> <Addr>: memory access breakpoint

Access: e (execute), r (read/write), w (write)
Size:: 1, 2, 4, 8 (always 1 with e)

ba e 0x2416fe
ba w4 0x0483DFE

### bl: list breakpoints

### bd <Breakpoints>: disable breakpoint

### be  <Breakpoints>: enable breakpoint

### bc  <Breakpoints>: clear breakpoint

## Memory

### Display

- da: ascii
du: unicode
dw: word
dd: dword
dq: qword
db: byte + ascii hexdump
dc: dword + ascii hexdump
dW: word + ascii hexdump
dp: pointer size
dD: double
df: float
dv: local variables
dt <Type> <Addr>: map struct type to addr

  Display memory content
  da @eax
  db 0xaabbccdd L10
  dt _PEB 0xdbe5ee1000
  
### Edit

- ea: ascii
eu: unicode
ew: word
ed: dword
eq: qword
eb: byte
ep: pointer size
eD: double
ef: float
eza: null-terminated ascii
ezu: null-terminated unicode

  Edit memory content
  ed 0x24e3fac2dd8 41414242
  eu 0x24e3fac2dd8 "hello"
  
### Search

- s -Flags <Range> <Pattern>
-b: byte
-w: word
-d: dword
-q: qword
-a: ascii
-u: unicode

  Search memory range for a specific pattern
  s -d @rsp L1000 48
  s -a 0x0f180771 L1000 "hello" 
  
### Fill

- f <Range> <Pattern>

  Fill memory range with a repeating pattern
  f 0x0012ff40 L20 'A' 'B' 'C'
  
### Compare

- c <Range> <Addr>

  Compare two memory areas
  c rgBuf1 (rgBuf1+0n100) rgBuf2
  c rgBuf1 L 0n100 rgBuf2
  c 0x1000 0x1007 rgBuf2
  
### Move

- m <Range> <Addr>

  Copy memory content from one location to another
  m 0xaaaaaaaa L10 0xbbbbbbbb
  
## General

### controls

- g: go (continue)
- p: step over
- t: step into
- gu: step out

### ?: evaluate expression

- ? <Num>: hex to decimal
- ? 0n<Num>: decimal to hex

### lm: list modules

### k: show stack backtrace

### ~: list threads

- ~<Num>s: switch to thread
- ~<Num>k: thread backtrace

### |: list processes

- |<Num>s: switch to process
- |<Num>k: process backtrace

### r: registers

- r <Reg>: read register

  r eax
  
- r <Reg>=<Val>: set register

  r eax = 0x41
  r eax = @ebx
  
### u: disassemble

- u <Addr>: disassemble from this address
- u <Range>: disassemble memory range
- uf <Addr>: disassemble function

### x: examine symbols

- x /f module!<Regex>: examine module functions matching this regex

  x /f kernel32!CreateFile*
  
## Bang Commands

### !teb | !teb <Addr>:
display thread environment block

### !peb | !peb <Addr>: 
display process environment block

### !handle: list all handles

- !handle <Val>: get handle type
- !handle <Val> f: get handle detailed info

### !address: view complete address space

### !address <Addr>: 
display status of a memory block 
(region size, protection, ...)

## Meta Commands

### .symfix: set the symbol path to point to the Microsoft symbol store.

### .reload /f module.dll: reload module symbols

### .detach: detach from a process

### .cls: clear commands window

### .childdbg <0|1>: attach to child process

### .writemem <FileName> <Range>: 
write contents of a memory range to a file

## Mahyar TajDini

### Mahyar@TajDini.net

### Github.com/mahyarx

### Linkedin.com/in/mahyartajdini

### TajDini.net

