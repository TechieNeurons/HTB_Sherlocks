# Sherlock Scenario
Wowza Grand College has opened a job application portal by creating a website for applicants to upload their resumes for HR to review. Recently, the SOC team observed suspicious enrollments to a certificate template in their ADCS infrastructure. The team began collecting evidence from the compromised domain controller to investigate the cause of the unauthorized certificate enrollments.

# Questions
#### Task 1 - When did the threat actor first interact with the College's IT Infrastructure?
- 2025-07-27 19:27:35
Looking at the file in the C folder we have `inetpub` folder which is linked to `IIS`, inside we have some logs, one of the file is bigger than the other `u_ex250727.log`, opening it we see `feroxbuster` usage by `143.198.231.177`, search for first appearance of this IP

#### Task 2 - What is the malicious IP address used for initial reconnaissance and discovery?
- 143.198.231.177
Cf. previous question

#### Task 3 - The threat actor uploaded a file using the file upload functionality. Under what name did the server store the uploaded resume file?
- Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf
Looking at the same log, at the end (after the `feroxbuster` use) we can spot what is the probable malicious resume upload:
```
2025-07-27 19:32:28 192.168.189.150 POST /default.aspx - 80 - 143.198.231.177 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 http://resumeupload.wowza.edu/default.aspx 200 0 0 5
```
After this upload we have multiple GET and POST request to a PDF file and in the parameters we can spot some files that are opened by the attacker (`LFI`), example here:
```
2025-07-27 19:33:41 192.168.189.150 POST /resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf fdir=C%3a%2f%2fUsers 80 - 143.198.231.177 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 http://resumeupload.wowza.edu/resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf?fdir=C%3a%2f%2fUsers 200 0 0 916
```

#### Task 4 - The threat actor uploaded another file in order to change the behavior of this website, allowing the first uploaded file to act as a webshell. What is the name of the uploaded file?
- web.config
Looked on internet on how to change file behavior

#### Task 5 - Using the webshell, the threat actor uploaded a file on the endpoint to facilitate initial remote access. Identify the full path of this file.
- c:\inetpub\wwwroot\resumes\8619.exe
Can be seen in IIS log, first file in the del parameter, he uploaded this file and many other like secretsdump etc.

#### Task 6 - The threat actor accessed a shared folder meant for the resume reviewers. What is the full path of the first file they retrieved?
- C:\Shares\ResumeReview\Certificate_for_sign.cer
We can see it in the IIS logs: `2025-07-27 19:34:23 192.168.189.150 GET /resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf get=C%3a%2fShares%2fResumeReview%2f%2fCertificate_for_sign.cer 80 - 143.198.231.177 Mozilla/5.0+(X11;+Linux+x86_64;+rv:128.0)+Gecko/20100101+Firefox/128.0 http://resumeupload.wowza.edu/resumes/Resume9_eba15ba0-81ca-4d0f-9fad-3fc1fc92c181.pdf?fdir=C%3a%2fShares%2f%2fResumeReview 200 0 0 24`

#### Task 7 - Who was the first ideal candidate the company was seeking?
- warlocksmurf
Open the MFT with hex editor, the file has the entry number 913, so I multiplied by 1024 to get the offset in MFT and move to it

#### Task 8 - A file was dropped to perform a potential Kerberoasting attack in the Active Directory environment. What is the name of this file?
- r.exe
From the file uploaded and seen in the del parameters it seems to be the most probable (probably rubeus)

#### Task 9 - Which service account was targeted by this active directory attack?
- WOWZA.EDU\ca_svc
Looking at the security.evtx EventID 4769 "Kerberos service ticket operation"

#### Task 10 - Attacker dropped another tool to exploit a misconfiguration in AD CS. When was this tool successfully created on the endpoint?
- 2025-07-27 19:52:03
The file used to exploit AD CS is certipy (we saw him in the IIS logs), for the creation time I used `NTFS Log Tracker` and parsed `$LogFile`, `$UsnJrnl:$J` and `$MFT` then made a search of `certipy` in `$UsnJrnl` and `$LogFile` and found the creation time in the `$UsnJrnl:$J` search result tab (at the top)

#### Task 11 - When was AD CS exploited successfully on the domain controller?
- 2025-07-27 19:56:38
First let's know more about these attacks: https://www.vaadata.com/en/blog/ad-cs-security-understanding-and-exploiting-esc-techniques/
Then let's open the `security.evtx` and filter the events to keep only `4886` and `4887`
The first `4886` is a ESC1 and followed by a `4887` meaning successful exploit.

#### Task 12 - Identify the name and version of the vulnerable certificate template exploited in the attack.
- PDFSigner v100.4
Same evtx filter on eventID `4900` to have the template modification

#### Task 13 - A new security descriptor was applied to the vulnerable certificate template and this security descriptor grants full control over the certificate template to a specific group. What is the name of that group?
- Authenticated Users
Cf. Previous question, in the details we have the old and new security descriptor

#### Task 14 - When was the certificate issued to the threat actor for a high-privilege user, allowing privilege escalation?
- 2025-07-27 19:57:55
After the certificate was modifier (EventID `4900`) we have two set of `4886` (certificate requested) and `4887` (certificate issued), the second one is the correct one, I don't see difference between first one and second one but the answer is the timestamp of the second one.

#### Task 15 - The threat actor successfully retrieved the NTLM hash of a high-privilege user using the newly issued certificate. What was the serial number of the certificate used to achieve this privilege escalation?
- 1D00000008A6E7524F029E603A000000000008
In `security.evtx` after getting the certificate we see multiple logon and logoff and other uninteresting action but at 2025-07-27 19:59:15 we see a kerberos authentication for the user administrator done with this certificate ID

#### Task 16 - The attacker exploited an Active Directory misconfiguration to gain access to Active Directory secrets stored on the domain controller. What is the MITRE ATT&CK ID for this technique?
- T1003.006
We can spot a DCSync, after the answer of the previous question we have a lot of EventID `4662` and in the properties we have UID like `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` corresponding to `DS-Replication-Get-Changes` (and others) and with the access mask `0x100` (Control Access) all these point to DCSync

#### Task 17 - When was the attack mentioned in the previous task successfully carried out?
- 2025-07-27 20:05:14
The logon and special logon just before accessing a lot of AD object

#### Task 18 - A Golden Ticket was issued using a previously dropped tool. What is the filename of this ticket?
- shinyboi_wowza_edu_2025_07_27_20_06_33_Administratorr_to_krbtgt@WOWZA.EDU.kirbi
We know rubeus was used, we can spot the name of the file in the IIS Logs, when he deleted the ticket

#### Task 19 - The threat actor used the web shell to delete all files involved in this operation. When did the deletion routine begin?
- 2025-07-27 20:11:13
IIS Logs