## Questions

Task 1 - What compiler timestamp is embedded in the malware binary? (UTC)
- 2089-10-01 03:41:58
PESTUDIO

---


Task 2 - What is the name of the suspicious packed section found in the executable?
- .CSS
PESTUDIO

---


Task 3 - Which encryption algorithm is used by the malware?
- RC4
The decryption function is DeleteSentence but wasn't able to recognize RC4 by myself, I ask AI to recognize

***


Task 4 - Which WinAPI function is leveraged to execute the shellcode?
- CallWindowProcA
Open in ILSPY

---

Task 5 - Which process is targeted by the shellcode for injection?
- msbuild.exe
Found in *inputData*

---


Task 6 - What technique is used to execute the second-stage payload?
- Process Hollowing

******* *********


Task 7 - Which Computer name does the second-stage malware check for to evade analysis environments? (lowercase)
- hal9th
In the entry we see the getComputerName call then later it's compared to the letter H and 9 and also this check check that the username is John doe, both corresponding to the defender sandbox
A bit guessing because the malware only check that the name start with H and a 9 in 4th place and the username is J and "o"

******


Task 8 - What string does the second-stage malware register to prevent multiple executions on the same host? (Format lowercase: string)
- approve_april
In the FUN_00416050 - first function call in the entry function

---


Task 9 - Which function address initializes the malware's internal string structure by setting the fields to zero?
- 0x40f3b0
In the FUN_00416050 - after registering the string, big loop using a lot this function

********


Task 10 - Besides FileZilla, which other file transfer client is targeted for credential extraction?
- winscp
In the strings

******


Task 11 - What is the function address that starts crawling the Steam process by acquiring its handle?
- 0x40ee70
Follow the string steam.exe, this string is given to a function and this function return is given to the answer function

********


Task 12 - What type of authentication artifact does the second-stage malware search for in Steam's process memory?
- JWT
In the previously found function we have multiple call like this `lVar5 = FUN_0040ead0(hProcess,"65 79 41 69 64 48 6C 77 49 6A 6F 67 49 6B 70 58 56 43 49 73",(LPCVOID)0x0,0(LPCVOID)0xffffffff,0xfff,pvVar2,auStack_218);`
The hex value is the base64 string for `{ "typ": "JWT",`

***


Task 13 - What unique hardcoded identifier does this second-stage malware instance use to identify itself during data exfiltration?
- ee4724586a69cda3db87344f07509f40
strings -n32

--- 


Task 14 - What special marker string did the second-stage malware use in the Discord crawling process?
- dQw4w9WgXcQ
Following the discord string we find the function and this string inside it

---


Task 15 - Which messaging platform does the second-stage malware exfiltrate stolen data to?
- telegram
In the strings

---

## Extracting second stage
1. Open the exe with dnSpy-x86
2. The program is "cut" in two class "Program" and "Publisher"
	1. "Program" contains the main, two windows API (VirtualProtect and CallWindowProcA), DeleteSentence (which is the decryption routine) and three variables dataKey which is used for decryption, *inputData* and *sectionContent* which will be interesting after.
	2. The main function is not doing much except launching the "Publisher" class
	3. The "Publisher" class is calling multiple time *DeleteSentence* which is decrypting *inputData* and *sectionContent*
	4. The *CallWindowProcA* is used to execute the shellcode but the shellcode is not executed directly
	5. first we go to the offset 392 of *inputData* for finding where the *sectionContent* will be loaded/injected
3. In dnSpy put a breakpoint on the *CallWindowProcA* line
4. In the menu click on: **Debug > Windows > Watch > Watch 1**
5. In the watch window that opened add `initial.Program.inputData` and `initial.Program.sectionContent`
6. Right click on both of them and *Save* to save them