# OpTinselTrace 3

## Speech
```
Oh no! Our IT admin is a bit of a cotton-headed ninny-muggins, ByteSparkle left his VPN configuration file in our fancy private S3 location! The nasty attackers may have gained access to our internal network. We think they compromised one of our TinkerTech workstations. Our security team has managed to grab you a memory dump - please analyse it and answer the questions! Santa is waiting…
```

## Analysis


## Questions
1. What is the name of the file that is likely copied from the shared folder (including the file extension)?
    - present_for_santa.zip
2. What is the file name used to trigger the attack (including the file extension)?
    - click_for_present.lnk
3. What is the name of the file executed by click_for_present.lnk (including the file extension)?
    - present.vbs
4. What is the name of the program used by the vbs script to execute the next stage?
    - powershell.exe
5. What is the name of the function used for the powershell script obfuscation?
    - WrapPresent
6. What is the URL that the next stage was downloaded from?
    - 77.74.198.52:445
7. What is the IP and port that the executable downloaded the shellcode from (IP:Port)?
    - http://77.74.198.52/destroy_christmas/evil_present.jpg
8. What is the process ID of the remote process that the shellcode was injected into?
    - 724
9. After the attacker established a Command & Control connection, what command did they use to clear all event logs?
    - Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log }
10. What is the full path of the folder that was excluded from defender?
    - C:\users\public
11. What is the original name of the file that was ingressed to the victim?
    - procdump.exe
12. What is the name of the process targeted by procdump.exe?
    - lsass.exe