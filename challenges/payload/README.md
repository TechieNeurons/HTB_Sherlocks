# Payload

## Speech
> You’ve completed Training Day — congrats, rookie. Now the real game begins. An unmarked binary just landed on your desk. It’s acting shady, tripping a few alarms, but no one's sure what it really is. Malware? Or just a misunderstood piece of code? Your mission: reverse-engineer the program, trace its behavior, and uncover the truth. Every line of code could be a clue—or a trap. Welcome to your first real case.

## Questions
Open file in PEStudio

1. What is the SHA256 hash of func_pointer.exe?
	> EDD41B4A819F917F81203424730AAF0C24CC95E40ACFC0F1BD90B11DADF58015
	- In the indicators tab for example

2. What compiler is being used?
	> MingW
	- In the string we see a lot of MingW string

3. What is the compilation date?
	> 2023-04-06 15:21:17
	- Can be found in the file-header tab

4. Is ASLR enabled? (True or False)
	> false
	- Can be found in the optional-header tab

5. What is the image base address?
	> 0x140000000
	- In the optional-header, the image-base data

6. What is the entry point?
	> 0x1125
	- Can be found in the indicators tab

---

We know (by launching it, letting it make his job one time) that at the end we have a window opening with the word HTB PWN U in it, and this window is from the process explorer.exe, so this malware is injecting the explorer.exe

7. What are the first 8 bytes of the encrypted payload that is being moved to allocated memory? (format: daffd563616c632e)
	> 8d098d59a01f830a
	- I found the decrypted one before the encrypted one ! Cf question 10 before checking this answer
	- First I check the Xref to the function which is doing the injection, I see only one call which is in the function fcn.140001d97
	- I put a breakpoint at the beginning of this function and step over the function call looking at the stack at the same time, I look at the stack address where the decoded payload will be store later (0x5FFC40) and I step over the instructions
	- When I step over the line: `0000000140001E2E	call func_pointer.1400017D0` The decoded payload appear on the stack which mean this function is decoding.
	- I took a look at this function in Ghidra:
```
  local_c = 0;
  local_10 = 0;
  local_14 = 0;
  for (i = 0; i < 0x40; i = i + 1) {
    iVar4 = i;
    if (i < 0) {
      iVar4 = i + 7;
    }
    uVar1 = local_c * 2;
    local_c = (local_14 >> 0x16 ^
              (int)(uint)*(byte *)(param_1 + i % param_2) >> ((byte)(iVar4 >> 3) & 0x1f) ^
              local_c >> 0x12 ^ local_10 >> 0x15) & 1 | uVar1;
    uVar2 = local_10 * 2;
    local_10 = (uVar1 & 0x100) >> 8 | uVar2;
    local_14 = (uVar2 & 0x400) >> 10 | local_14 * 2;
  }
  for (j = 0; j < param_4; j = j + 1) {
    uVar5 = local_c >> 8;
    uVar1 = local_14 ^ local_10;
    uVar2 = local_14 & local_10;
    local_1d = 0;
    for (k = 0; k < 8; k = k + 1) {
      uVar6 = (uVar2 >> 10 ^ uVar5 & uVar1 >> 10) & 1 ^
              (local_14 >> 0x16 & local_10 >> 0x15 ^
              local_c >> 0x12 & (local_14 >> 0x16 ^ local_10 >> 0x15)) & 1;
      local_1d = local_1d | (byte)(uVar6 << ((byte)k & 0x1f));
      uVar3 = local_c * 2;
      local_c = uVar6 | uVar3;
      uVar6 = local_10 * 2;
      local_10 = (uVar3 & 0x100) >> 8 | uVar6;
      local_14 = (uVar6 & 0x400) >> 10 | local_14 * 2;
    }
    *(byte *)(param_5 + j) = *(byte *)(param_3 + j) ^ local_1d;
  }
  return;
```

	- And here we have the call to the function: "FUN_1400017d0(0x140004020,iVar4,0x140004040,uVar3,*(longlong *)((longlong)alStack_78 + lVar1));"
	- This function seems to use bitshift and xor to decode the payload, the first parameters looks like the key, the second one seems to be a length the third one seems to be the encoded data the fourth seems to be the size of the text to decode and the last one the address to the output buffer.
	- Looking again at x64dbg:
```
0000000140001E18 | 41:89C9                  | mov r9d,ecx                                 |
0000000140001E1B | 4C:8D05 1E220000         | lea r8,qword ptr ds:[140004040]             |
0000000140001E22 | 89C2                     | mov edx,eax                                 |
0000000140001E24 | 48:8D05 F5210000         | lea rax,qword ptr ds:[140004020]            | 0000000140004020:"UUUUUUUU"
0000000140001E2B | 48:89C1                  | mov rcx,rax                                 |
0000000140001E2E | E8 9DF9FFFF              | call func_pointer.1400017D0                 |
```

	- Here we have the key (all the U) Cf next question
	- To find the address of the encoded payload we can look at the third arguments, put a breakpoint on the function call, the *first argument* (the key) is in **rax** the *second argument* is in **rdx** *third argument* in **r8** and *fourth argument* in **r9**
	- Go to the address given by **r8** and tak the first 8 bytes

8. What is the key for decryption in hex?
	> 0x5555555555555555
	- Cf previous question, U is 55 in hex

9. What is the address of the decrypted payload?
	> 0x5FFC40
	- Cf following question

10. What are the first 8 bytes of the decrypted payload that is being moved to allocated memory? (format: daffd563616c632e)
	> fc4881e4f0ffffff
	- In the strings I saw the VirtualAllocEx and WriteProcessMemory API (not seen in the import) I used Xref to find where these strings are used:
```
0x140001c03      lea     rax, [str.VirtualAllocEx] ; 0x1400050a9
0x140001c0a      mov     rdx, rax
0x140001c0d      mov     rax, qword [GetProcAddress] ; 0x14000a228
0x140001c14      call    rax
0x140001c16      mov     qword [0x1400090c8], rax
0x140001c1d      lea     rax, [str.kernel32.dll] ; 0x140005050
0x140001c24      mov     rcx, rax
0x140001c27      mov     rax, qword [GetModuleHandleA] ; 0x14000a220
0x140001c2e      call    rax
0x140001c30      mov     rcx, rax
0x140001c33      lea     rax, [str.WriteProcessMemory] ; 0x1400050b8
0x140001c3a      mov     rdx, rax
0x140001c3d      mov     rax, qword [GetProcAddress] ; 0x14000a228
0x140001c44      call    rax
```
These lines are storing the address of the different function from kernel32.dll in the stack
After we have:
```
0000000140001CBD	mov r10,qword ptr ds:[<&VirtualAllocEx>] | r10:VirtualAllocEx
0000000140001CC4	mov edx,dword ptr ss:[rbp+20]
0000000140001CC7	mov rax,qword ptr ss:[rbp+10]
0000000140001CCB	mov dword ptr ss:[rsp+20],20
0000000140001CD3	mov r9d,1000
0000000140001CD9	mov r8,rdx
0000000140001CDC	mov edx,0
0000000140001CE1	mov rcx,rax
0000000140001CE4	call r10                                    | r10:VirtualAllocEx
0000000140001CE7	mov qword ptr ss:[rbp-8],rax
0000000140001CEB	mov r10,qword ptr ds:[<&WriteProcessMemory> | r10:WriteProcessMemory
0000000140001CF2	mov r8d,dword ptr ss:[rbp+20]
0000000140001CF6	mov rcx,qword ptr ss:[rbp+18]
0000000140001CFA	mov rdx,qword ptr ss:[rbp-8]
0000000140001CFE	mov rax,qword ptr ss:[rbp+10]
0000000140001D02	mov qword ptr ss:[rsp+20],0
0000000140001D0B	mov r9,r8
0000000140001D0E	mov r8,rcx
0000000140001D11	mov rcx,rax
0000000140001D14	call r10                                    | r10:WriteProcessMemory
0000000140001D17	mov r10,qword ptr ds:[<&CreateRemoteThread> | r10:CreateRemoteThread
0000000140001D1E	mov rdx,qword ptr ss:[rbp-8]
0000000140001D22	mov rax,qword ptr ss:[rbp+10]
0000000140001D26	mov qword ptr ss:[rsp+30],0
0000000140001D2F	mov dword ptr ss:[rsp+28],0
0000000140001D37	mov qword ptr ss:[rsp+20],0
0000000140001D40	mov r9,rdx
0000000140001D43	mov r8d,0
0000000140001D49	mov edx,0
0000000140001D4E	mov rcx,rax
0000000140001D51	call r10                                    | r10:CreateRemoteThread
```
This code is first allocating memory then writing code to it and finally creating a thread with the written code has beginning of the thread.
Just before the call to r10 containing WriteProcessMemory the different arguments are placed in the registry, the function signature is: WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, NULL)
And by looking at the line before the call we have:
| API Parameter | Register | Value    |
| ------------- | -------- | -------- |
| hProcess      | RCX      | [rbp+18] |
| lpBaseAddress | RDX      | [rbp-8]  |
| lpBuffer      | R8       | [rbp+10] |
| nSize         | R9       | [rbp+20] |
Going to the address given by R8 give us the injected code, also this address answer the previous question

11. There are several functions that are not in the import table but are invoked. Which of these functions starts with V?
	> VirtualAllocEx
	- By looking at the strings we find it, also we see import of VirtualProtect but not VirtualAlloc