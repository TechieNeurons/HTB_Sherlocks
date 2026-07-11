WinDBG

Task 1 - Provide the operating system version.
10.0.10240.16384
```
!analyze -v
```

Task 2 - Provide the full path of the malicious executable used to gain initial access.
C:\Users\s1rx\Downloads\update.exe
```
# First I looked at the module loaded by update.exe and notepad.exe
# Clicking on the exe name we get this
0:000> lm o t
start             end                 module name
00000000`00400000 00000000`0044e000   update    Mon Jun  8 17:17:28 2020 (5EDED518)
00007fff`373b0000 00007fff`37657000   wininet   Thu Jul  9 20:21:21 2015 (559F3A31)
00007fff`37f00000 00007fff`38174000   comctl32  Thu Jul  9 20:27:30 2015 (559F3BA2)
00007fff`3a150000 00007fff`3a165000   NapiNSP   Thu Jul  9 20:23:46 2015 (559F3AC2)
00007fff`3a320000 00007fff`3a33a000   pnrpnsp   Thu Jul  9 20:22:51 2015 (559F3A8B)
00007fff`3a3b0000 00007fff`3a3bd000   winrnr    Thu Jul  9 20:18:32 2015 (559F3988)

0:000> lmDvmupdate
Browse full module list
start             end                 module name
00000000`00400000 00000000`0044e000   update     (no symbols)           
    Loaded symbol image file: update.exe
    Image path: C:\Users\s1rx\Downloads\update.exe
    Image name: update.exe
    Browse all global symbols  functions  data  Symbol Reload
    Timestamp:        Mon Jun  8 17:17:28 2020 (5EDED518)
    CheckSum:         000514C2
    ImageSize:        0004E000
    Mapping Form:     Loaded
    Translations:     0000.04b0 0000.04e4 0409.04b0 0409.04e4
    Information from resource tables:
```

Task 3 - How many threads did the malicious process use?
6
```
0:000> ~
.  0  Id: c24.bdc Suspend: 0 Teb: 00007ff5`ffffd000 Unfrozen
   1  Id: c24.3ec Suspend: 0 Teb: 00007ff5`ffff9000 Unfrozen
   2  Id: c24.a14 Suspend: 0 Teb: 00007ff5`ffff7000 Unfrozen
   3  Id: c24.e30 Suspend: 0 Teb: 00007ff5`ffff4000 Unfrozen
   4  Id: c24.448 Suspend: 0 Teb: 00007ff5`ffffb000 Unfrozen
   5  Id: c24.8 Suspend: 0 Teb: 00007ff5`ffece000 Unfrozen
```

Task 4 - Provide the named pipe (IPC channel) used by the malicious process.
MSSE-1641-server
```
strings64.exe .\update.DMP | Select-String 'pipe'
```

Task 5 - Provide the PID of the injected process. Provide the Answer in decimal.
2336
```
# Open notepad.dmp
# type ~ for listing thread, the PID is before the TID
```

Task 6 - At what time was the last thread created for the injected process? Provide the timestamp in UTC.
2025-11-05 01:09:12 UTC
```

```

Task 7 - Provide the BaseAddress of the injected shellcode.
b1\`20870000
```
# We have one thread with a start very weird
0:000> ~*
.  0  Id: 920.c28 Suspend: 0 Teb: 00007ff7`8d76e000 Unfrozen
      Start: notepad!WinMainCRTStartup (00007ff7`8dc23fe0)
      Priority: 0  Priority class: 32  Affinity: 1
   1  Id: 920.3a8 Suspend: 0 Teb: 00007ff7`8d76c000 Unfrozen
      Start: 000000b1`20870000
      Priority: 0  Priority class: 32  Affinity: 1
   2  Id: 920.5fc Suspend: 0 Teb: 00007ff7`8d768000 Unfrozen
      Start: ntdll!TppWorkerThread (00007fff`47309040)
      Priority: 0  Priority class: 32  Affinity: 1
   3  Id: 920.2d0 Suspend: 0 Teb: 00007ff7`8d764000 Unfrozen
      Start: ntdll!TppWorkerThread (00007fff`47309040)
      Priority: 0  Priority class: 32  Affinity: 1
```

Task 8 - Provide the C2 server IP address.
101.10.25.4
```
> strings64.exe notepad.dmp | Select-String -Pattern '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
[101.10.25.4](http://101.10.25.4:8891/submit.php?id=1019752184)
```

Task 9 - Provide the name of the C2 framework used by the threat actor.
Cobalt Strike
```

```