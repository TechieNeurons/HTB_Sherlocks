# Jinkies

## Speech
```
You’re a third-party IR consultant and your manager has just forwarded you a case from a small-sized startup named cloud-guru-management ltd. They’re currently building out a product with their team of developers, but the CEO has received word of mouth communications that their Intellectual Property has been stolen and is in use elsewhere. The user in question says she may have accidentally shared her Documents folder and they have stated they think the attack happened on the 6th of October. The user also states she was away from her computer on this day. There is not a great deal more information from the company besides this. An investigation was initiated into the root cause of this potential theft from Cloud-guru; however, the team has failed to discover the cause of the leak. They have gathered some preliminary evidence for you to go via a KAPE triage. It’s up to you to discover the story of how this all came to be. Warning: This sherlock requires an element of OSINT and players will need to interact with 3rd party services on internet.
```

## Analysis
### LiveResponse
1. ipconfig.txt :
```
Host Name . . . . . . . . . . . . : velmad100
IPv4 Address. . . . . . . . . . . : 192.168.157.144
```
2. NetSystemInfo
```
Administrator            DefaultAccount           Guest                    
test                     Velma                    WDAGUtilityAccount       
```

### Triage
1. 

## Questions
1. Which folders were shared on the host? (Please give your answer comma separated, like this: c:\program files\share1, D:\folder\share2)
    > C:\Users\Velma\Documents, C:\Users
    - Registry key : Lanmanserver in SYSTEM hive
2. What was the file that gave the attacker access to the users account?
    > bk_db.ibd
    - By visiting the folder shared folder, we found thisfile linked to bdd data
3. How many user credentials were found in the file?
    > 216
    - Strings on the file then count the number of gmail, because all users seems to have gmail
4. What is the NT hash of the users password?
    > 967452709ae89eaeef4e2c951c3882ce
    - `impacket-secretsdump -system ./TriageData/C/Windows/system32/config/SYSTEM -security ./TriageData/C/Windows/system32/config/SECURITY -sam ./TriageData/C/Windows/system32/config/SAM LOCAL`
    ```
    Impacket v0.11.0 - Copyright 2023 Fortra

    [*] Target system bootKey: 0x0fcab1a9630872ac6f23b1d98a3d9ed6
    [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:b47a9f2da3e6d7b88213822b52232627:::
    test:1001:aad3b435b51404eeaad3b435b51404ee:3dbde697d71690a769204beb12283678:::
    Velma:1002:aad3b435b51404eeaad3b435b51404ee:967452709ae89eaeef4e2c951c3882ce:::
    [*] Dumping cached domain logon information (domain/username:hash)
    [*] Dumping LSA Secrets
    [*] DPAPI_SYSTEM 
    dpapi_machinekey:0xd27147a1d420cbf19e1e4bb099624276113ad3e0
    dpapi_userkey:0x5ec03c836ea7d746d3a0af059fb9644edbb05155
    [*] L$_SQSA_S-1-5-21-3466369480-1315555486-2413066615-1001 
    Security Questions for user S-1-5-21-3466369480-1315555486-2413066615-1001: 
    - Version : 1
    | Question: What was your first pet's name?
    | |--> Answer: 123
    | Question: What was your childhood nickname?
    | |--> Answer: 123
    | Question: What is the first name of your oldest cousin?
    | |--> Answer: 123
    [*] L$_SQSA_S-1-5-21-3466369480-1315555486-2413066615-1002 
    Security Questions for user S-1-5-21-3466369480-1315555486-2413066615-1002: 
    - Version : 1
    | Question: What is the name of the city where you were born?
    | |--> Answer: Glasgow
    | Question: What was your first pet's name?
    | |--> Answer: Snowy
    | Question: What was your childhood nickname?
    | |--> Answer: Jeepers
    [*] NL$KM 
    0000   ED DA 79 C0 84 A6 B7 77  67 79 2D 65 B3 31 4C 84   ..y....wgy-e.1L.
    0010   E4 89 4E 71 17 71 5E 53  67 31 19 76 22 A0 87 CE   ..Nq.q^Sg1.v"...
    0020   25 C6 FF CD A0 76 D2 DC  95 F5 81 03 75 9F 96 2A   %....v......u..*
    0030   FC 99 16 93 F8 28 DD 57  C3 7C F8 2E 66 78 86 C6   .....(.W.|..fx..
    NL$KM:edda79c084a6b77767792d65b3314c84e4894e7117715e536731197622a087ce25c6ffcda076d2dc95f58103759f962afc991693f828dd57c37cf82e667886c6
    [*] Cleaning up... 
    ```
5. Does this password match that found in the previous file? (Yes or No)
    > Yes
    - peakTwins2023fcvelma.dinkley@gmail.comvelmavelma dinkley
    - I put the password from the file (peakTwins2023fc) to https://www.browserling.com/tools/ntlm-hash
6. What was the time the attacker first interactively logged on to our users host?
    > 2023-10-06 17:17:23
    - I opened the file : `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx`
7. What's the first command the attacker issues into the Command Line?
    > whoami
    - Open sysmoin file in evtx
8. What is the name of the file that the attacker steals?
    > Version-1.0.1 - TERMINAL LOGIN.py
    - In sysmon we can see this at 1:18:31PM
9. What's the domain name of the location the attacker ex-filtrated the file to?
    > pastes.io
    - In the chrome history or autopsy web history
10. What is the handle of the attacker?
    > pwnmaster12
    - In the MFT we can find a file named lean.txt in Pictures of velma