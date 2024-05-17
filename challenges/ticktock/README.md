# TickTock

## Speech
```
Gladys is a new joiner in the company, she has recieved an email informing her that the IT department is due to do some work on her PC, she is guided to call the IT team where they will inform her on how to allow them remote access. The IT team however are actually a group of hackers that are attempting to attack Forela.
```

## Analysis

## Questions
1. What was the name of the executable that was uploaded as a C2 Agent?
    > merlin.exe
2. What was the session id for in the initial access?
    > -2102926010
3. The attacker attempted to set a bitlocker password on the C: drive what was the password?
    > reallylongpassword
4. What name was used by the attacker?
    > Fritjof Olfasson
5. What IP address did the C2 connect back to?
    > 52.56.142.81
6. What category did Windows Defender give to the C2 binary file?
    > VirTool:Win32/Myrddin.D
7. What was the filename of the powershell script the attackers used to manipulate time?
    > Invoke-TimeWizard.ps1
8. What time did the initial access connection start?
    > 2023/05/04 11:35:27
9. What is the SHA1 and SHA2 sum of the malicious binary?
    > ac688f1ba6d4b23899750b86521331d7f7ccfb69:42ec59f760d8b6a50bbc7187829f62c3b6b8e1b841164e7185f497eb7f3b4db9
10. How many times did the powershell script change the time on the machine?
    > 2371
11. What is the SID of the victim user?
    > S-1-5-21-3720869868-2926106253-3446724670-1003