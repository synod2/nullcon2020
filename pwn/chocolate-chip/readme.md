chocolate-chip 
---------------
pwn , 486pts

desc 
---------------
```
```
- using Z3 solve 
- GOT overwrite

files 
---------------
-main 
-libc.so.6(glibc 2.27->ubuntu 18.04)


checksec 
---------------
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

solution 
---------------

시작하면 ch0c0l4te-chip 이라는 파일을 open함. 
파일에서 %lu로 읽어온 내용을 변수에 저장하고 파일을 닫는다.


```
int __fastcall open_f(const char *a1, __int64 a2)
{
  FILE *stream; // ST18_8

  stream = fopen(a1, "r");
  __isoc99_fscanf(stream, "%lu", a2);
  return fclose(stream);
}
```

그다음 읽어온 내용을 xor하여 결과를 따로 저장하는 구문이 있다.

```
signed __int64 *__fastcall xor_f(signed __int64 *a1, __int64 a2)
{
  signed __int64 *result; // rax

  result = a1;
  *a1 = a2 ^ 0x5DEECE66DLL;
  return result;
}
```

이후 xor되어 저장된 내용을 비트연산하는데, 해당 연산의 결과값은 배열에 저장되고
결과값을 다시한번 연산하는 식으로 10번 반복되어 배열에 저장된다. 


```
for ( i = 0; i <= 9; ++i )
  {
    v4 = calc(&xor_res);
    dword_6010A0[i] = v4;
  }
  
----------------------------------

__int64 __fastcall calc(_QWORD *a1)
{
  *a1 = 5DEECE66DLL * *a1 + 11;
  return *a1 >> 16;
}
```

이후 배열에 저장된 내용을 출력하는데, 
0-2-4-6-8 , 1-3-5-7-9 순으로 출력한다. 
-> 0 1 2 3 4  / 5 6 7 8 9 

그 다음, 최초에 파일에서 읽어왔던 내용을 rbp-2C 위치에 저장하고 
rbp-40 위치에 1F4만큼 입력을 받은 다음, 파일에서 다시 내용을 읽어와 2C위치에 저장한 내용과 비교하여
일치하지 않으면 프로그램을 종료시킨다. 즉, 카나리를 만든 셈이고 
카나리의 값은 출력해준 비트연산의 결과값을 역연산해 알아내게끔 만든 것이다. 

연산 마지막에 16비트만큼 오른쪽 시프트 연산을 하기 때문에 하위 4바이트가 잘린다. 
그리고 값을 복사할때 ecx 레지스터로 복사하기 때문에 연산 결과의 하위 8바이트만 남게 된다.
상당히 많은 값들이 잘려나가기 때문에 원본값의 복원이 조금 힘들어보인다. 

이때 연산에 들어가는 인자값들을 보면, 첫번째 연산 결과값을 시프트연산 하기 전 값이
이후 연산의 인자값이 되어 들어가는걸 볼 수 있다. 
출력되는 값은 시프트 연산 이후 + 8바이트 만큼 자른 값이다. 
즉, 잘만 이용하면 잘린 4바이트에 대한 어느정도 유추가 가능할 수도 있단 이야기. 
다만 이경우에도 레지스터 크기로 인해 하위 16바이트만 저장된다. 

정리하면, 이전 연산결과 * 0x5DEECE66D + 11 한 값의 비트연산 결과가 출력되고,
메모리에 저장되는 이전 연산결과는 비트연산 전의 결과값이 저장되지만 하위 16바이트만 저장된다는 거다. 

식을 세워보면, r(n+1) = r(n) * a + b >> 11 로 세워진다. 

따라서, 임의의 난수 x를 인자로 하여 해당 연산을 10회 반복하여 결과가 일치하는 값을 계산하여 찾아보면 될것같다. 
풀이에는  z3 모듈을 사용한다. 

우선 8바이트짜리 시드를 찾아야 하므로, 64비트 미지수를 선언해준다. 
이후에 해당 미지수를 가지고 위에서 한 비트 연산을 반복,
프로그램에서 리턴해준 결과와 동일한지를 비교하는 수식을 추가한다.
이때 주의할 점은, 연산의 결과자체는 다음 연산을 위해 활용되므로 따로 저장해야 하고,
원래의 값과 비교할 것은 연산결과에 비트연산 + 하위 8바이트만 따로 연산한 값이 되어야 한다.

그러므로, 값은 r(n) * 0x5Deece66d + 11 이고
추가해야 할 계산식은 ( (r(n) >> 16) & 0xffffffff == res_str[i] ) 가 된다. 

```
seed = z3.BitVec('seed',64)
seed = seed ^ 0x5Deece66d
equ = seed
for i in range(0,10) : 
    equ = equ * 0x5Deece66d + 11
    s.add( ( equ >> 16) & 0xffffffff == res_str[i] ) #filtering last 8 bytes
    
log.info(s.check())    #check find soulution
canary = s.model()[seed].as_long() 
log.info(canary)
```
z3에서 check() 함수는 답이 있을경우 sat를 , 없을경우 unsat을 출력하는 함수이다. 
이렇게 시드를 찾으면 그다음부터는 rop를 진행한다. 

입력위치가 rbp-0x40 이고 카나리(시드)의 위치는 rbp-2c이다. 0x14 바이트 입력 후 카나리가 들어간다.
setvbuf의 got를 oneshot 가젯으로 덮어쓰는 got overwrite를 이용했다.

* printf 함수를 이용해 lbic를 leak 하려다 보니 에러가 발생하는데, 예전에 찾아봤던 바로는
  이럴땐 ret를 한번 더 하고나서 printf를 호출하면 해결된다고 한다. 
  다만 이렇게 하면 이 다음번부터 printf / scanf 계열 함수는 사용하지 못하게 된다.
  원인은 스택의 크기가 8의 홀수 배수이여야 한다는듯. 

