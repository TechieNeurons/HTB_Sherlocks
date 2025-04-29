# Takedown

## Speech
> We've identified an unusual pattern in our network activity, indicating a possible security breach. Our team suspects an unauthorized intrusion into our systems, potentially compromising sensitive data. Your task is to investigate this incident.

## Questions
1. From what domain is the VBS script downloaded?
	> escuelademarina.com
	- The packet 23 contain a vbs script, 4 packets berfore we can see a domain name escuelademarina.com
2. What was the IP address associated with the domain in question #1 used for this attack?
	> 165.22.16.55
	- Source of the request is 10.3.19.101 and dest is the IP of the domain, the smb server
3. What is the filename of the VBS script used for initial access?
	> AZURE_DOC_OPEN.vbs
	- The name of the vbs script
4. What was the URL used to get a PowerShell script?
	> badbutperfect.com/nrwncpwo
	- Download the vbs script and at the end we have the url
5. What likely legit binary was downloaded to the victim machine?
	> AutoHotKey.exe
	- Extract the HTTP object in the wireshark capture, in the previous url we have the filename, this powershell script contain this exe file which look pretty legit
6. From what URL was the malware used with the binary from question #5 downloaded?
	> http://badbutperfect.com/jvtobaqj
	- in the powershell script
7. What filename was the malware from question #6 given on disk?
	> script.ahk
	- like the one before
8. What is the TLSH of the malware?
	>  T15E430A36DBC5202AD8E3074270096562FE7DC0215B4B32659C9EF16835CF6FF9B6A1B8 
	- extract the script.ahk from HTTP object of pcap then put it on virustotal
9. What is the name given to this malware? Use the name used by McAfee, Ikarus, and alejandro.sanchez.
	> DarkGate
	- Community tab of virustotal
10. What is the user-agent string of the infected machine?
	> Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
	- Find an HTTP packet from the 10.3.19.101
11. To what IP does the RAT from the previous question connect?
	> 103.124.105.78
	- Look at the communication from the infected machine