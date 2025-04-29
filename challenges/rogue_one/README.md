# Rogue One

## Speech
```
Your SIEM system generated multiple alerts in less than a minute, indicating potential C2 communication from Simon Stark's workstation. Despite Simon not noticing anything unusual, the IT team had him share screenshots of his task manager to check for any unusual processes. No suspicious processes were found, yet alerts about C2 communications persisted. The SOC manager then directed the immediate containment of the workstation and a memory dump for analysis. As a memory forensics expert, you are tasked with assisting the SOC team at Forela to investigate and resolve this urgent incident.
```

## Analysis
1. It's a windows memory dump
2. I like to begin with : `/opt/volatility3/vol.py -f ./20230810.mem windows.pstree` but the pstree is really big... So not very easy to read, and I didn't see anything with it...
3. So I launched : `/opt/volatility3/vol.py -f ./20230810.mem windows.cmdline` which give us the command line that launched each process, and we can see : `6812 svchost.exe "C:\Users\simon.stark\Downloads\svchost.exe"`
    - I'm not an expert but I think svchost.exe shouldn't be in the Downloads folder...
    - We can take some notes
    - First, the PID of the bad process is **6812**
    - Second, the name of the user **simon.stark** (I know we already had it in the briefing)
4. Now let's go back to the pstree in order to see the parent and children of this svchost
    - we can see the parent of **6812** : `** 7436 7400 explorer.exe 0x9e8b8c4d2080 75 - 1 False 2023-08-10 11:14:07.000000 N/A	\Device\HarddiskVolume3\Windows\explorer.exe C:\WINDOWS\Explorer.EXE C:\WINDOWS\Explorer.EXE` (to be honest it's a bit useless, we just see the malware has been launched from the explorer/by the user)
    - Also the children :
    ```
    *** 6812 7436 svchost.exe 0x9e8b87762080 3 - 1 False 2023-08-10 11:30:03.000000 N/A	\Device\HarddiskVolume3\Users\simon.stark\Downloads\svchost.exe	"C:\Users\simon.stark\Downloads\svchost.exe" C:\Users\simon.stark\Downloads\svchost.exe
    **** 4364 6812 cmd.exe 0x9e8b8b6ef080 1 - 1 False 2023-08-10 11:30:57.000000 N/A \Device\HarddiskVolume3\Windows\System32\cmd.exe C:\WINDOWS\system32\cmd.exe C:\WINDOWS\system32\cmd.exe
    ***** 9204 4364 conhost.exe 0x9e8b89ec7080 3 - 1 False 2023-08-10 11:30:57.000000 N/A \Device\HarddiskVolume3\Windows\System32\conhost.exe \??\C:\WINDOWS\system32\conhost.exe 0x4 C:\WINDOWS\system32\conhost.exe
    ```
    - Our malicious process spawned a cmd and the cmd opened a connection (conhost)
5. What next ? We could try to recover the original malware, first scan for the file : `/opt/volatility3/vol.py -f ./20230810.mem windows.filescan | grep 'svchost.exe' | grep simon`
    - We get : 
    ```
    0x9e8b909045d0 \Users\simon.stark\Downloads\svchost.exe	216
    0x9e8b91ec0140 \Users\simon.stark\Downloads\svchost.exe	216
    ```
    - Then we recover with : `/opt/volatility3/vol.py -f ./20230810.mem windows.dumpfiles --virtaddr 0x9e8b909045d0` (I did with the first one, but we can use any of them, we get the same thing with both)
6. We could do more, like analysing the exe, but without any idea of what we are looking for it's a bit boring... Let's go in the questions to have a "path"

## Questions
1. Please identify the malicious process and confirm process id of malicious process.
    > 6812
    - cf. Analysis > 3
2. The SOC team believe the malicious process may spawned another process which enabled threat actor to execute commands. What is the process ID of that child process?
    > 4364
    - cf. Analysis > 4
3. The reverse engineering team need the malicious file sample to analyze. Your SOC manager instructed you to find the hash of the file and then forward the sample to reverse engineering team. Whats the md5 hash of the malicious file?
    > 5bd547c6f5bfc4858fe62c8867acfbb5
    - cf Analysis > 5
4. In order to find the scope of the incident, the SOC manager has deployed a threat hunting team to sweep across the environment for any indicator of compromise. It would be a great help to the team if you are able to confirm the C2 IP address and ports so our team can utilise these in their sweep.
    > 13.127.155.166:8888
    - Take a look at the network connection done by the process we incriminate
    - The interesting part :
    ```
    $ /opt/volatility3/vol.py -f ./20230810.mem windows.netstat                                                               
    Volatility 3 Framework 2.7.0
    Progress:  100.00		PDB scanning finished                        
    Offset	Proto	LocalAddr	LocalPort	ForeignAddr	ForeignPort	State	PID	Owner	Created

    0x9e8b90fe82a0	TCPv4	172.17.79.131	64263	20.54.24.148	443	ESTABLISHED	6136	svchost.exe	2023-08-10 11:31:18.000000 
    0x9e8b8aedeab0	TCPv4	172.17.79.131	64239	192.229.221.95	80	CLOSE_WAIT	8224	SearchApp.exe	2023-08-10 11:28:48.000000 
    0x9e8b8cb58010	TCPv4	172.17.79.131	64254	13.127.155.166	8888	ESTABLISHED	6812	svchost.exe	2023-08-10 11:30:03.000000 
    0x9e8b905ed260	TCPv4	172.17.79.131	64217	23.215.7.17	443	CLOSE_WAIT	8224	SearchApp.exe	2023-08-10 11:28:45.000000 
    0x9e8b9045f8a0	TCPv4	172.17.79.131	63823	20.198.119.84	443	ESTABLISHED	3404	svchost.exe	2023-08-10 11:14:21.000000 
    0x9e8b8cee4010	TCPv4	172.17.79.131	64237	13.107.213.254	443	CLOSE_WAIT	8224	SearchApp.exe	2023-08-10 11:28:47.000000 
    0x9e8b8b2e4a20	TCPv4	172.17.79.131	64218	20.198.118.190	443	ESTABLISHED	3404	svchost.exe	2023-08-10 11:28:45.000000 
    ```
    - we can see PID 6812 which is svchost has established a connection with 13.127.155.166:8888
5. We need a timeline to help us scope out the incident and help the wider DFIR team to perform root cause analysis. Can you confirm time the process was executed and C2 channel was established?
    > 10/08/2023 11:30:03
    - See the response to the previous question, we have the timestamp, just the date is not in the order asked
6. What is the memory offset of the malicious process?
    > 0x9e8b87762080
    - cf. Analysis > 4
7. You successfully analyzed a memory dump and received praise from your manager. The following day, your manager requests an update on the malicious file. You check VirusTotal and find that the file has already been uploaded, likely by the reverse engineering team. Your task is to determine when the sample was first submitted to VirusTotal.
    > 10/08/2023 11:58:10
    - Put the md5 in virustotal and go in details and look at the date of first submission :)