# Speech
> Bob, a senior software engineer at Acme Inc., was taking a break from correcting AI code to check in with his favorite gaming community. One of the newer members shared a new program that can make mods for a popular game. Eager to try new things, when he ran it as administrator (as instructed), all of his files were deleted and replaced! He immediately called the help desk, so they locked his machine and an incident response was called!

# Questions
1. Right from the start, based on the incident details, the .TXT file's contents, and the extension appended to the other .TXT file, what type of malware infection is this?
	> ransomware
	- ...
2. What mechanism does MCModMaker-v.1.4.exe use to send information back to the C2 server?
	> webhook
	- open in IDA,  in the function "sendToDiscord" we see in the discord URL "webhook"
	- can also be seen in the main_main
3. What command does MCModMaker-v.1.4.exe run suggesting that it is meant to execute other binaries or scripts?
	> powershell -ep bypass
	- Goes in the main_main, we see the different command launched (whoami, hostname, curl, powershell, the goteem.exe file etc.)
4. What is the value of the API key contained within the URL which suggests it enumerates geolocation data?
	> ZVBOKX3P8H7
	- Same as previous question
5. What domain is the C2 server that serves the ransomware payload?
	> goteem.htb
	- Same as previous question
6. While analyzing the MCModMaker-v.1.4.exe, what format is the data that is returned to the C2 server?
	> application/json
	- in the function "sendToDiscord"
7. What specific filetype is enumerated by goteem.exe for encryption?
	> TXT
	- The encrypt file we get is a txt :D
8. What is the full string that's displayed when goteem.exe enumerates a restricted Windows folder?
	> Skipping directory: %s (access denied)
	- open goteem.exe with ida
	- in the main_findTxtFiles_func1 function
9. Within the encryptFile function, in case file was read successfully, what is the function name found at the call instruction?
	> crypto_aes_NewCipher
	- Go in the encryptFile (stay in asm not disassemble)
	- after the first block we have a path that loop, not interested in it
	- The other path we see a call to os_ReadFile and two path from there
	- the left path do a runtime_convTstring and if we follow this path at the end we have : "Error reading file %s: %v\n", so not interested in this one
	- The right path we see a call to crypto_aes_NewCipher which is coherent because the file will be encrypted
10. What is the decryption key?
	> 6368616e676520746869732070617373
	- after quite some time !
	- I started at main_encryptFile and look for XREF to see where it's called, it's called from main_main_gowrap1 which is called in main_main
	- and in main_main if we go back after the reference to the wrapper we have this string sent to the stack (all the element use to create the AES cipher are from the stack)
11. What is the name of the project in the encrypted .TXT file?
	> AI Coding Chatbot
	- because it look like it will be hard to find the IV and GCM tag I'll use the bruh.exe which decipher if we provide the key
	- I did : .\bruh.exe --key 6368616e676520746869732070617373 after downloading bruh.exe and the encrypted txt
	- at the end : Found .goteem files: C:\Users\User\Downloads\probably_important.txt.goteem C:\probably_important.txt.goteem Decrypted and restored file: C:\Users\User\Downloads\probably_important.txt