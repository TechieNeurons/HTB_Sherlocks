# Holmes 2025 2: The Watchman's Residue

## Scenario
With help from D.I. Lestrade, Holmes acquires logs from a compromised MSP connected to the city’s financial core. The MSP’s AI helpdesk bot looks to have been manipulated into leaking remote access keys - an old trick of Moriarty’s.

## Questions
#### Task 1 - What was the IP address of the decommissioned machine used by the attacker to start a chat session with MSP-HELPDESK-AI?
- 10.0.69.45
In wireshark, look for API communication


#### Task 2 - What was the hostname of the decommissioned machine?
- WATSON-ALPHA-2
filtering on previous IP

#### Task 3 - What was the first message the attacker sent to the AI chatbot?
- Hello Old Friend
The first POST of the attacker IP

#### Task 4 - When did the attacker's prompt injection attack make MSP-HELPDESK-AI leak remote management tool info?
- 2025-08-19 12:02:06
Timestamp in the json returned by the AI, timestamp of the answer to the injection not timestamp of the injection message...

#### Task 5 - What is the Remote management tool Device ID and password?
- 565963039:CogWork_Central_97&65
In the follow HTTP conversation between IP and AI

#### Task 6 - What was the last message the attacker sent to MSP-HELPDESK-AI?
- JM WILL BE BACK
Logs JSON returned by the AI

#### Task 7 - When did the attacker remotely access Cogwork Central Workstation?
- 2025-08-20 09:58:25
In the `Connections_incoming.txt` file inside the `TRIAGE_IMAGE_COGWORK-CENTRAL\C\Program Files\TeamViewer` folder

#### Task 8 - What was the RMM Account name used by the attacker?
- James Moriarty
Just like the previous question

#### Task 9 - What was the machine's internal IP address from which the attacker connected?
- 192.168.69.213
Look for "punch received a=" in the teamviewer log file

#### Task 10 - The attacker brought some tools to the compromised workstation to achieve its objectives. Under which path were these tools staged?
- C:\Windows\Temp\safe\
Same file as before, later in the file look for write files

#### Task 11 - The attacker staged a browser credential harvesting tool on the compromised system. How long did this tool run before it was terminated? (Provide your answer in milliseconds, rounded to the nearest thousand)
- 8000
In the UserAssist (NTUSER.DAT)

#### Task 12 - The attacker executed a OS Credential dumping tool on the system. When was the tool executed?
- 2025-08-20 10:07:08
In USN Journal

#### Task 13 - The attacker exfiltrated multiple sensitive files. When did the exfiltration start? (UTC)
- 2025-08-20 10:12:07
Look for send file in TeamViewer logs

#### Task 14 - Before exfiltration, several files were moved to the staged folder. When was the Heisen-9 facility backup database moved to the staged folder for exfiltration?
- 2025-08-20 10:11:09
USNJournal + TeamViewer logs 

#### Task 15 - When did the attacker access and read a txt file, which was probably the output of one of the tools they brought, due to the naming convention of the file?
- 2025-08-20 10:08:06
Jumplist

#### Task 16 - The attacker created a persistence mechanism on the workstation. When was the persistence setup?
- 2025-08-20 10:13:57
SOFTWARE registry, winlogon

#### Task 17 - What is the MITRE ID of the persistence subtechnique?
- T1547.004
Google is your friend

#### Task 18 - When did the malicious RMM session end?
- 2025-08-20 10:14:27
In the connection incoming logs

#### Task 19 - The attacker found a password from exfiltrated files, allowing him to move laterally further into CogWork-1 infrastructure. What are the credentials for Heisen-9-WS-6?
- 
