Task 1 - What is sha256sum hash of argument_baby_1.exe ?
dc6267608ddfcc5c80571ccd46475a03fb667baf8620d0e91c93ccacacf97ef6
```
pestudio
```

Task 2 - Can you find development enviroment of malware author (e.g:ide) ?
Visual Studio
```
pestudio -> indicators -> file>signature
```

Task 3 - What CPU architecture was argument_baby_1.exe compiled for ?
32 bit
```
pestudio -> indicators -> file>type
```

Task 4 - Is argument_baby_1.exe a symbol-stripped binary?
false
```
pestudio -> file-header -> debug-stripped
```

Task 5 - Retrieve the full PDB file path from the debug information of argument_baby_1.exe
C:\Users\HTB\Desktop\argument\Release\argument.pdb
```
pestudio -> debug
```

Task 6 - The malware author was using a Windows OS. What was the associated username?
HTB
```
pestudio -> debug
```

Task 7 - What calling convention is used in argument_baby_1.exe ?
cdecl
```
Open in ghidra
```

Task 8 - How is the 1st argument passed to the function in argument_baby_1.exe?
esp
```
In the cdecl calling convention the arguments are push on the stack, ESP is the stack pointer
```

Task 9 - How is the 2nd argument passed to the function in argument_baby_1.exe?
esp+4
```
Each arguments is +4 because 32 bit
We see it clearly for FUN_00401100
```

Task 10 - How is the 3rd argument passed to the function in argument_baby_1.exe?
esp+8

Task 11 - How is the 4th argument passed to the function in argument_baby_1.exe?
esp+c

Task 12 - How is the 5th argument passed to the function in argument_baby_1.exe?
esp+10

Task 13 - Which CPU register holds the function's return value in argument_baby_1.exe?
eax
```
eax is the register for holding the results
```

Task 14 - What calling convention is used in argument_baby_2.exe ?
fastcall
```
Open in ghidra
Example FUN_00401100
But a lot of cdecl and stdcall
```

Task 15 - How is the 1st argument passed to the function in argument_baby_2.exe?
ecx
```
FUN_00401100 show us the arguments
```

Task 16 - How is the 2nd argument passed to the function in argument_baby_2.exe?
edx
```
FUN_00401100 show us the arguments
```

Task 17 - How is the 3rd argument passed to the function in argument_baby_2.exe?
esp
```
Same function, from the 3rd arguments they are pushed on the stack
```

Task 18 - How is the 4th argument passed to the function in argument_baby_2.exe?
esp+4

Task 19 - How is the 5th argument passed to the function in argument_baby_2.exe?
esp+8

Task 20 - What CPU architecture was argument_baby_3.exe compiled for ?
64 bit
```
I open in ghidra, ghidra give this info when he scan the binary
Can also be seen by the address and registers used in ghidra
```

Task 21 - How is the 1st argument passed to the function in argument_baby_3.exe?
rcx
```
Search for a function that give the arguments address (seems to be using fastcall 64 bits)
FUN_140001070
```

Task 22 - How is the 2nd argument passed to the function in argument_baby_3.exe?
rdx

Task 23 - How is the 3rd argument passed to the function in argument_baby_3.exe?
R8

Task 24 - How is the 4th argument passed to the function in argument_baby_3.exe?
R9

Task 25 - How is the 5th argument passed to the function in argument_baby_3.exe?
rsp+20
```
FUN_140001180
```

Task 26 - In the case of argument_baby_3.exe, which CPU register stores the function's return value?
RAX
```
RAX and EAX are the return value by convention
```
