Task 1 - What is the MD5 hash of the malware?
fd46d178474f32f596641ff0f7bb337e
```
HashMyFiles
```

Task 2 - What programming language is used to write the malware?
golang
```
DIE
```

Task 3 - What is the name of the folder the malware copies itself to after the initial run?
Systemlogs
```
Open in IDA
Search for main_main function, go to main_hide function
After getting current path make a new file in this folder
```

Task 4 - What registry key does the malware modify to achieve persistence?
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\HealthCheck
```
follow execution, open the call to main_lurk and follow
```

Task 5 - What FQDN does the malware attempt to connect to?
malware.invalid.com
```
Look at the function main_heist
```

Task 6 - Which Windows API function does the malware call to check drive types?
GetDriveType
```
Filter on sys_windows and see this one
Called in main_outbreak
```

Task 7 - Which Go standard library function does the malware use to schedule periodic execution?
NewTicker
```
Goes in main_main then main_repeat, here we have the call to newTicker
```

Task 8 - What encoding does the malware use to decode server responses?
base64
```
in main_touchbase he does a get request
when successful changed byte to string and then send to base64 decode
```

Task 9 - The malware communicates with a backend server via a POST request. What are the names of the fields in the request body, separated by commas and listed alphabetically?
name,version
```
in main_collectData he get osversion and hostanme
then call formatData, in it he is renaming the field to name and version
```
