# Streamer

## Speech
> Simon Stark is a dev at forela who recently planned to stream some coding sessions with colleagues on which he received appreciation from CEO and other colleagues too. He unknowingly installed a well known streaming software which he found by google search and was one of the top URL being promoted by google ads. Unfortunately things took a wrong turn and a security incident took place. Analyze the triaged artifacts provided to find out what happened exactly.

## Analysis

#### 1
We don't know much and we have a lot of artifacts, I started by transforming the $MFT into a CSV file: `MFTECmd.exe -f "C:\Users\User\Desktop\Streamer\Acquisition\C\$MFT" --csv "." --csvf mft.csv` then I opened this file with *Timeline Explorer*.
First thing I look for is web downloaded file, because the scenario told us the user download something, for that I filtered on every *Zone Id Contents* (except *blanks*) to have all the downloaded file.

I have all these files:

| Parent Path                                                   | File Name                                    | Downloaded from: (URL)                                                                 |
| ------------------------------------------------------------- | -------------------------------------------- | -------------------------------------------------------------------------------------- |
| .\Users\Simon.stark\Downloads                                 | default:Zone.Identifier                      | HostUrl=https://myparentime.blogspot.com/feeds/posts/default                           |
| .\Users\Simon.stark\Downloads                                 | default(1):Zone.Identifier                   | HostUrl=https://myparentime.blogspot.com/feeds/1084677616575035861/comments/default    |
| .\Users\Simon.stark\Downloads                                 | default(2):Zone.Identifier                   | HostUrl=https://myparentime.blogspot.com/feeds/posts/default                           |
| .\$Recycle.Bin\S-1-5-21-3239415629-1862073780-2394361899-1602 | $RUMATHW.zip:Zone.Identifier                 | HostUrl=https://codeload.github.com/ezimuel/PHP-Secure-Session/zip/refs/heads/master   |
| .\Users\Simon.stark\Documents\Streaming Software              | Obs Streaming Software.zip:Zone.Identifier   | HostUrl=http://obsproicet.net/download/v28_23/OBS-Studio-28.1.2-Full-Installer-x64.zip |
| .\Users\Simon.stark\Documents                                 | PHPNotesForProfessionals.pdf:Zone.Identifier | HostUrl=about:internet                                                                 |

The blogpost files named default doesn't look very interesting

Then we have the "PHP-Secure-Session" github which could potentially be interesting but not sure for the moment.

Finally we have **obsproicet.net** which seems to be a typosquatting for obs studio, a soft for streaming, and the scenario told us about the streaming will of the user.
This one looks very promissing, alors we have, for example, this link: https://x.com/Cyb3rMaddy/status/1924850780802027691 which tell us that this domain has been abused. We are on the right track.

By searching for "obs" and filtering on .zip I noticed the user renamed the file, the file was named "OBS-Studio-28.1.2-Full-Installer-x64.zip" and he renamed it to "C:\Users\Simon.stark\Documents\Streaming Software\Obs Streaming Software.zip" (renamed at 2023-05-05 10:22:23)

#### 2
We can get the list of the files extracted by looking at the files in the "Streaming Software" folder by filtering on the folder name created by the user (*Streaming Software*)
By filtering like that we have a list of all the extracted file.

Because we have a lot of .exe and other file, let's dive into the prefetch to see what was executed and in which order.
I parsed the whole prefetch folder, to have as much as i can: `PECmd.exe -d "C:\Users\User\Desktop\Streamer\Acquisition\C\Windows\prefetch" --csv "C:\Users\User\Desktop\Streamer" --csvf parsed_pf.csv`
Let's begin with the prefetch timeline analysis with TimelineExplorer, and filter on "obs":
![[00_prefetch_timeline.png]]

The executed file is the only exe in the "parent folder" *Obs Streaming Software* which is named *OBS-Studio-28.1.2-Full-Installer-x64.exe*

I also parsed the amcache to have more info about this execution: `AmcacheParser.exe -f "C:\Users\User\Desktop\Streamer\Acquisition\C\Windows\AppCompat\Programs\Amcache.hve" --csv C:\Users\User\Desktop\Streamer`
In the file *Amcache_UnassociatedFileEntries* we have things like the hash of the executable.

Don't really know how to find what the exe did so I searched for persistence mechanism, after a bit of looking around I found the creation of a new scheduled task (*looking at the security evtx and filtering on 4698 (creation of new scheduled task)*)
![[01_new_scheduled.png]]


## Questions
1. What's the original name of the malicious zip file which the user downloaded thinking it was a legit copy of the software?
	> OBS-Studio-28.1.2-Full-Installer-x64.zip
	- Cf. Analysis 1
2. Simon Stark renamed the downloaded zip file to something else. What's the renamed Name of the file alongside the full path?
	> C:\Users\Simon.stark\Documents\Streaming Software\Obs Streaming Software.zip
	- Cf. Analysis 1
3. What's the timestamp when the file was renamed?
	> 2023-05-05 10:22:23
	- Cf. Analysis 1
4. What's the Full URL from where the software was downloaded?
	> http://obsproicet.net/download/v28_23/OBS-Studio-28.1.2-Full-Installer-x64.zip
	- Cf. Analysis 1
5. Dig down deeper and find the IP Address on which the malicious domain was being hosted.
	> 13.232.96.186
	- Look at the file: *Streamer\Acquisition\C\Windows\System32\winevt\Logs\Archive-Microsoft-Windows-DNS-Client%4Operational-2023-05-05-10-31-18-874.evtx*
	- Search for "obsproicet" and look at all the DNS request, we finally found the "QueryResults" with the IP
6. Multiple Source ports connected to communicate and download the malicious file from the malicious website. Answer the highest source port number from which the machine connected to the malicious website.
	> 50045
	- In the folder *Streamer\Acquisition\C\Windows\System32\LogFiles\Firewall* we have a firewall logfile with all the connection made by the machine
	- I used powershell to filter on the IP: `Select-String -Path .\pfirewall.log -Pattern "13.232.96.186"`
7. The zip file had a malicious setup file in it which would install a piece of malware and a legit instance of OBS studio software so the user has no idea they got compromised. Find the hash of the setup file.
	> 35e3582a9ed14f8a4bb81fd6aca3f0009c78a3a1
	- Cf. Analysis 2
8. The malicious software automatically installed a backdoor on the victim's workstation. What's the name and filepath of the backdoor?
	> C:\Users\Simon.stark\Miloyeki ker konoyogi\lat takewode libigax weloj jihi quimodo datex dob cijoyi mawiropo.exe
	- Cf. Analysis 2
9. Find the prefetch hash of the backdoor.
	> D8A6D943
	- Open the parsed prefetch file (not the prefetch timeline) and filter on the name of the exe (a part of the name, I filtered on D8A6D943)
10. The backdoor is also used as a persistence mechanism in a stealthy manner to blend in the environment. What's the name used for persistence mechanism to make it look legit?
	> COMSurrogate
	- Look at *Task Name* given in the task creation
11. What's the bogus/invalid randomly named domain which the malware tried to reach?
	> oaueeewy3pdy31g3kpqorpc4e.qopgwwytep
	- I reopened the evtx of the DNS request Archive-Microsoft-Windows-DNS-Client%4Operational-2023-05-05-10-31-18-874.evtx and filter to have logs from the 5/5/23 3:23:20 and after
	- This time is when the task was created
12. The malware tried exfiltrating the data to a s3 bucket. What's the url of s3 bucket?
	> bbuseruploads.s3.amazonaws.com
	- Same as before, look at all the DNS request done
13. What topic was simon going to stream about in week 1? Find a note or something similar and recover its content to answer the question.
	> Filesystem Security
	- Go to the MFT CSV file opened in Timeline Explorer, filter for Simon.stark and filter to have only .txt
	- We have a file named "Week 1 plan.txt" and the size is 57 which mean this file is stored in the MFT
	- Open the $MFT with an hex editor and search for "week" to find the content of the file
14. What's the name of Security Analyst who triaged the infected workstation?
	> CyberJunkie
	- ...
15. What's the network path from where acquisition tools were run?
	> \\DESKTOP-887GK2L\Users\CyberJunkie\Desktop\Forela-Triage-Workstation\Acquisiton and Triage tools
	- Open the NTUSER.DAT file of Simon.stark with the shellbags explorer