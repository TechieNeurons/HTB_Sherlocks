# Sherlock Scenario
At AcmeSys Corp, employee John Miller reported unusual PC behavior after installing a Chrome update and running a command in File Explorer. You have been provided with a triage image with KAPE for investigation.

# Questions
#### Task 1 - When was the user's last successful login to the system?
- 2025-08-11 06:46:52
Open the `security.evtx`, filter on EventID `4624`, from the most recent event go back in time, look for `Logon Type 2` which is a user logon

#### Task 2 - When did the victim last open the browser they regularly used on the system?
- 2025-08-11 07:12:17
Goes in the prefetch, multiple chrome so it seems to be his regular browser.
Using Zimlmerman Tools: `.\PECmd.exe -d "C:\Users\techie\Desktop\LogForge\2025-08-11T075021_Kape_Output\C\Windows\prefetch" --csv "C:\Users\techie\Desktop\LogForge" --csvf parsed_prefetch.csv`
Open the timeline in `TimelineExplorer`

#### Task 3 - The user accessed a malicious website as a result of phishing attempt. What is the URL?
- https://cool-bunny-55393d.netlify.app/
Open the chrome database, open: `LogForge\2025-08-11T075021_Kape_Output\C\Users\user\AppData\Local\Google\Chrome\User Data\Default` with sqlitebrowser

#### Task 4 - After the user visited the website, they were directed to copy a command from the website and enter it into the File Explorer search bar. Shortly after, strange behavior was noticed. What is the full URL that installed the reverse shell on the victim's device?
- http://192.168.26.128:8000/rev.ps1
To know what the user typed in search bar we need to look at NTUSER.DAT registry
And open the key: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`
Can be found in `LogForge\2025-08-11T075021_Kape_Output\C\Windows\System32\winevt\logs\Microsoft-Windows-PowerShell%4Operational.evtx`

#### Task 5 - This attack preys on non-technical users by luring them into traps and manipulating them into unknowingly executing commands on the system. Based on the analysis of the previously identified command, what is this type of attack called?
- FileFix
I search online for: "clickfix variants powershell explorer search bar"
https://www.huntress.com/blog/dont-sweat-clickfix-techniques

#### Task 6 - After the attack, the user noticed that Notepad had opened with a message left by the attacker. What is the email address of the attacker?
- 0xSh3rl0cK@protonmail.com
Looking at notepad.exe in the prefetch we spot: `\VOLUME{01db30ae7dff85ee-b07e284e}\USERS\PUBLIC\README.TXT,`, we need this file.
Parsing the MFT: `.\MFTECmd.exe -f "C:\Users\techie\Desktop\LogForge\2025-08-11T075021_Kape_Output\C\MFT" --csv "C:\Users\techie\Desktop\LogForge\" --csvf parsed_mft.csv`
Looking for the README.TXT file in the public folder we get this entry number: `93420`
Should be resident, 93420 x 1024 = 95662080, let's open MFT in hex editor and move to this decimal offset

#### Task 7 - The attacker downloaded malware to infect the victim's device. What is the full path of the malicious malware file?
- C:\Windows\Temp\WindowsUpdate.exe
in `LogForge\2025-08-11T075021_Kape_Output\C\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx`, filter on EventID `11` for file creation, we can see powershell creating this file after the README.txt

#### Task 8 - What is the product name of this malicious file?
- Virtuoso
In sysmon, filter on eventID 1 for process execution, found the answer at 2025-08-11 07:32:47

#### Task 9 - The malware created several directories on the system. Under which path were these files created?
- C:\Windows\
Filter on EventID 11 in sysmon, go just after the execution found in previous question

#### Task 10 - A script file was staged on the machine by the malware. What is the full command used to achieve this?
- "C:\Windows\System32\cmd.exe" /c copy Cricket Cricket.bat & Cricket.bat
Switch to Sysmon EventID 1, look for process creation after the file creation and we get this

#### Task 11 - What is the full path of the staged script file?
- C:\Users\user\AppData\Local\Temp\Cricket.bat
Can be seen at the creation in Sysmon EventID 11

#### Task 12 - The attacker dropped an automation utility on the system with a legacy file format. What is the full path of this newly dropped file?
- C:\Users\user\AppData\Local\Temp\316094\Intranet.pif
Sysmon EventID 11

#### Task 13 - What is the name and version of the utility?
- AutoIt 3.3.14.3
Look at process creation details of the .pif process

#### Task 14 - Using this utility, the attacker dropped another script on the system. What is the name of this script?
- Virtuoso.js
EventID 11 following previous question

#### Task 15 - In order to evade defenses for unattended access, the malware executed commands to look for EDR and antivirus presence on the system. What is the full command line of the second command used to achieve this?
- findstr -I "avastui avgui bdservicehost nswscsvc sophoshealth"
Sysmon EventID 1

#### Task 16 - What is the full command used to set up persistence on the system?
- cmd /k echo [InternetShortcut] > "C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Virtuoso.url" & echo URL="C:\Users\user\AppData\Local\Immersive Creations Co\Virtuoso.js" >> "C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Virtuoso.url" & exit

Just after the previous command