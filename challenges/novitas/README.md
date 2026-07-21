Task 1 - When does the suspicious process start?
2024-09-05 15:58:11
> Not a lot of weird processes, I used `/opt/volatility3/vol.py -f memory.raw -r pretty windows.pstree > pstree.txt` with my **PRETTY PSTREE VISUALIZER**, we can see a dllhost.exe process (weird)
> called by mmc.exe, the start time of mmc.exe is the suspicious process start time (the malware)
> Looking at the cmd: `"C:\Windows\system32\mmc.exe" "C:\Users\IEUser\AppData\Local\Temp\MicrosoftEdgeDownloads\91617dd3-f62f-4c28-ba7d-8769251040b3\family_image.msc"`

Task 2 - What is the size of the archive file containing the malware in bytes?
1971433
> We know the file was downloaded from Edge (seen in the cmd of the process) so I looked for the Edge history file `/opt/volatility3/vol.py -f memory.raw windows.filescan | grep -i history`, dumped it: `/opt/volatility3/vol.py -f memory.raw windows.dumpfiles --virtaddr 0xa7850f527080`
> Then open in SQLiteBrower and look at the Downloads table

Task 3 - The user unzipped the archive containing the malware. Write down the names of the files contained in the unzipped archive and sort them alphabetically.?
family_image.msc,family_image.obj
> Need to recover $MFT, $LogFile and $usnjournal and parse them with NTFS Log Tracker to parse the three files
> Also we know they are family_image.msc (from the command) and family_image.obj (from the mftscan of volatility3) 

Task 4 - How many NAT (native) modules are loaded into suspicious process in total?
98
> I used: `/opt/volatility3/vol.py -f memory.raw -r pretty windows.dlllist --pid 3120 | wc -l`
> Substract the .ni.dll which are .NET and not native, also substract the process himself (mmc.exe) and the header of the table, in total 104-6

Task 5 - Submit the assembly address of all CLR modules in Ascending order.
0000000004E62FD0,0000000004E630F0,0000000004E63690,0000000004E638D0,0000000004E63B10
> CLR modules are custom code modules written in .NET
> Use the minidump from memprocfs

Task 6 - What is the name of the malicious module loaded?
Ad00bce9305554c87927205710b17699f
> In the previous list we can look at the module name, they all have a full path but not this one

Task 7 - Dump malicious dll using dlldump only helps you get the correct size of image but the data inside is messed up. Try to use other way to dump dll from memory and submit md5 of dll
e67f5692a35b8e40049e30ad04c12b41
> I did it with windbg command: `!SaveModule 00007ff894956b70 C:\Users\techie\Desktop\malicious.dll`

Task 8 - What is the xor key used to obfuscate strings in the dll?
a7ad965a-50b4-4846-bfb2-2282839f8d0c
> Open the DLL in DnSpy, a lot of code, in the last class (Ac696fde...) we have two function, one of them do an xor, rename it to spot it easily later, then look at the others function, they all call XOR function with a base64 and the same string which is the key

Task 9 - What is the IP of C2 server and port the malware connects to?
149.28.22.48:8484
> It's a cobalt strike, use 1768 on the mmc process minidump

Task 10 - What is the md5 hash of shellcode used for the final stage?

> The code is using environnement variable to reconstruct the shellcode, recover the shellcode from envars