Task 1 - Who is the suspicious sender of the email?
eu-health@ca1e-corp.org
Open the mail

Task 2 - What is the legitimate server that initially sent the email?
BG3O293MB0335.SRBL293.PROD.OUTLOOK.COM
Open with notepad++

Task 3 - What is the attachment filename?
Health_Clearance-December_Archive.zip
In the header, like before with notepad++

Task 4 - What is the Document Code?
EU-HMU-24X
Open the pdf

Task 5 - What is the full URL of the C2 contacted through a POST request?
https://health-status-rs.com/api/v1/checkin
For this one and the following question do a strings on the lnk file and look at the command (ending with iex)

Task 6 - The malicious script sent three pieces of information in the POST request. What is the registry key from which the last one is retrieved?
HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid

Task 7 - Then the script downloads and executes a second stage from another URL. What is the domain?
advent-of-the-relics-forum.htb.blue

Task 8 - A set of credentials was used to access the previous resource. Retrieve them.
svc_temp:SnowBlackOut_2026!
