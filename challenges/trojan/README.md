# Trojan

## Speech
> John Grunewald was deleting some old accounting documents when he accidentally deleted an important document he had been working on. He panicked and downloaded software to recover the document, but after installing it, his PC started behaving strangely. Feeling even more demoralised and depressed, he alerted the IT department, who immediately locked down the workstation and recovered some forensic evidence. Now it is up to you to analyze the evidence to understand what happened on John's workstation.

## Questions

First the memory dump

1. What is the build version of the operating system?
	> 19041
	- `/opt/volatility3/vol.py -f memory.vmem windows.info.Info`
2. What is the computer hostname?
	> DESKTOP-38NVPD0
	- First find the SYSTEM hive:
	```
	$ /opt/volatility3/vol.py -f memory.vmem windows.registry.hivelist.HiveList | grep SYSTEM
	0x8a0d9148a000.0\REGISTRY\MACHINE\SYSTEM	Disabled
	```
	- Then print the ComputerName key:
	```
	$ /opt/volatility3/vol.py -f memory.vmem windows.registry.printkey.PrintKey --offset 0x8a0d9148a000 --key 'ControlSet001\control\ComputerName\ComputerName'   
	Volatility 3 Framework 2.26.2
	Progress:  100.00		PDB scanning finished                        
	Last Write Time	Hive Offset	Type	Key	Name	Data	Volatile

	2023-05-22 07:00:31.000000 UTC	0x8a0d9148a000	REG_SZ	\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName	(Default)	mnmsrvc	False
	2023-05-22 07:00:31.000000 UTC	0x8a0d9148a000	REG_SZ	\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName	ComputerName	DESKTOP-38NVPD0	False
	```

3. What is the name of the downloaded ZIP file?
	> Data_Recovery.zip
	- Let's look at the downloads folder
	```
	$ /opt/volatility3/vol.py -f memory.vmem windows.filescan.FileScan | grep Downloads                                          
	0xb381761d2df0.0\Users\John\Downloads\desktop.ini
	0xb381776bdc20	\Users\John\Downloads\desktop.ini
	0xb38177761640	\Users\John\Downloads\Data_Recovery.zip
	0xb38177778ed0	\Users\John\Downloads
	0xb381777796a0	\Users\John\Downloads
	0xb38177870530	\Users\John\Downloads\Data_Recovery\Recovery_Setup.exe
	0xb3817799d690	\Users\John\Downloads\Data_Recovery
	0xb3817799e180	\Users\John\Downloads\Data_Recovery\Recovery_Setup.exe
	0xb381779a0d40	\Users\John\Downloads\Data_Recovery
	0xb381779a1e70	\Users\John\Downloads\Data_Recovery
	0xb381779a2af0	\Users\John\Downloads\Data_Recovery\Recovery_Setup.exe
	0xb381779a5b60	\Users\John\Downloads\Data_Recovery\Recovery_Setup.exe
	```
4. What is the domain of the website (including the third-level domain) from which the file was downloaded?
	> praetorial-gears.000webhostapp.com
	- Let's take a look at the MFT ADS for that: `/opt/volatility3/vol.py -f memory.vmem windows.mftscan.ADS`
5. The user then executed the suspicious application found in the ZIP archive. What is the process PID?
	> 484
	- Look at the process list: `/opt/volatility3/vol.py -f memory.vmem windows.pslist`
6. What is the full path of the suspicious process?
	> C:\Users\John\Downloads\Data_Recovery\Recovery_Setup.exe
	- `/opt/volatility3/vol.py -f memory.vmem windows.cmdline | grep 484`
7. What is the SHA-256 hash of the suspicious executable?
	> c34601c5da3501f6ee0efce18de7e6145153ecfac2ce2019ec52e1535a4b3193
	- Extracting from volatility didn't worked :/ dunno why...
	- Open the ad1 file with FTK Imager and go to folder Downloads and extract the file then hash it

We are with the ad1 file now !

8. When was the malicious program first executed?
	> 2023-05-30 02:06:29
	- Extract the prefetch of the malware `RECOVERY_SETUP.EXE-A808CDAB.pf`
	- `C:\Tools\PECmd\PECmd.exe -f RECOVERY_SETUP.EXE-A808CDAB.pf --csv "." --csvf recovery.csv`
	- Then open the csv file with timeline explorer (I take the value of Previous Run0)
9. How many times in total has the malicious application been executed?
	> 2
	- Same as previous question
10. The malicious application references two .TMP files, one is IS-NJBAT.TMP, which is the other?
	> IS-R7RFP.TMP
	- In the same file as before in the "files loaded" column
11. How many of the URLs contacted by the malicious application were detected as malicious by VirusTotal?
	> 4
	- Copy paste the sha in virutotal and look at the relation table
12. The malicious application downloaded a binary file from one of the C2 URLs, what is the name of the file?
	> puk.php
	- Can get it from the wireshark of from virustotal, in wireshark when we follow the http stream we see the download of a file from this puk.php
13. Can you find any indication of the actual name and version of the program that the malware is pretending to be?
	> FinalRecovery v3.0.7.0325
	- By looking at the hash online we can find it in sandbox report
	- Found it in the interesting extracted strings of hybrid analysis report