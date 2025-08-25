## Speech
> It is Friday afternoon and the SOC at Edny Consulting Ltd has received alerts from the workstation of Jason Longfield, a software engineer on the development team, regarding the execution of some discovery commands. Jason has just gone on holiday and is not available by phone. The workstation appears to have been switched off, so the only evidence we have at the moment is an export of his mailbox containing today's messages. As the company was recently the victim of a supply chain attack, this case is being taken seriously and the Cyber Threat Intelligence team is being called in to determine the severity of the threat.

## Questions
1. Identify the sender of the suspicious email.
	> theodore.todtenhaupt@developingdreams.site
	- I simply did: `grep -H "From: " *` (to have all the senders)
	- The weirdest mail is: `Opportunity to Invest in NFT Game Project.eml`
2. The suspicious email came from a custom domain, identify its creation date.
	> 2025-01-31
	- Search for the domain name on virustotal: developingdreams.site
3. The domain was registered shortly before the suspicious email was received, which likely corresponds to the time when the threat actor was planning this campaign. Which MITRE ATT&CK sub-technique of the Resource Development tactic corresponds to this activity?
	> T1583.001
	- Search for the mitre ATT&CK resource development tactic then look for the corresponding one, acquiring domain
4. The previously identified domain appears to belong to a company, what is the full URL of the company's page on X (formerly Twitter)?
	> https://x.com/Develop_Dreams
	- In VirusTotal we can see their website:  www.developingdreams.site
	- using the wayback machine we can go on this website and find the X account
5. Reading the suspicious email carefully, it appears that the threat actor first contacted the victim using the previously identified social media profile. Which MITRE ATT&CK sub-technique of the Resource Development tactic corresponds to this activity?
	> T1585.001
	- Look at the subtechnique of the tactic
6. What is the name of the game the threat actor would like us to collaborate on?
	> DeTankWar
	- We can see the two project of the company on their website, only one is in beta like said in the mail
7. What is the SHA-256 hash of the executable shared by the threat actor?
	> 56554117d96d12bd3504ebef2a8f28e790dd1fe583c33ad58ccbf614313ead8c
	- download the zip from the website and use the password: DTWBETA2025 to extract and get the hash
8. As part of the preparation of the tools for the attack, the threat actor hosted this file, presumably malware, on its infrastructure. Which MITRE ATT&CK sub-technique of the Resource Development tactic corresponds to this activity?
	> T1608.001
	- looking at the same mitre page
9. Based on the information you have gathered so far, do some research to identify the name of the threat actor who may have carried out this attack.
	> Moonstone Sleet
	- Can be seen in the community tab of virutotal of the sha256sum of the malware
10. What nation is the threat actor believed to be associated with?
	> north korea
	- same as before
11. Another campaign from this threat actor used a trojanized version of a well-known software to infect victims. What is the name of this tool?
	> putty
	- Go on the mitre page of the APT
12. Which MITRE ATT&CK technique corresponds to the activity of deploying trojanized/manipulated software?
	> T1195.002
	- same as previous question
13. Our company wants to protect itself from other supply chain attacks, so in documenting more about this threat actor, the CTI team found that other security researchers were also tracking a group whose techniques closely match Moonstone Sleet, and discovered a new supply chain campaign around the end of July 2024. What technology is this campaign targeting?
	> npm
	- I search "Moonstone Sleet" on Google and then filtered on date, to have only things between 28 July 2024 and 31 July 2024, first result from datadog is talking about fake npm packages
14. We now need some indicators to be able to rule out that other systems have been compromised. What is the name and version of the lastest malicious package published? (Format: package-name vX.X.X)
	> harthat-hash v1.3.3
	- In the datadog article
15. The malicious packages downloaded an additional payload from a C2 server, what is its IP address?
	> 142.111.77.196
	- In the datadog article, just after the version
16. The payload, after being renamed, is finally executed by a legitimate Windows binary to evade defenses. Which MITRE ATT&CK technique corresponds to this activity?
	> T1218.011 
	- In the article they explain the execution, downloading and using rundll32 for executing, which correspond to this technique