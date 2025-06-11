# Operation Blackout 2025: Ghost Thread

#Windows #APIMonitor #process_injection #tls

## Speech
> Byte Doctor suspects the attacker used a process injection technique to run malicious code within a legitimate process, leaving minimal traces on the file system. The logs reveal Win32 API calls that hint at a specific injection method used in the attack. Your task is to analyze these logs using a tool called API Monitor to uncover the injection technique and identify which legitimate process was targeted.

## Analysis
Open the ampx64 file with APIMonitor, filter on the inject.exe and follow the API Call to get all the answer to how this thing work

## Questions
1. What process injection technique did the attacker use?
    > Thread Local Storage
    - Open the ida file and see that the TLS callback function is used, which mean function launch before main, which mean using the TLS functionnality, also check MITRE process injection page
2. Which Win32 API was used to take snapshots of all processes and threads on the system?
    > CreateToolhelp32Snapshot
    - 
3. Which process is the attacker's binary attempting to locate for payload injection?
    > notepad.exe
    - 
4. What is the process ID of the identified process?
    > 16224
    - 
5. What is the size of the shellcode?
    > 511
    - 
6. Which Win32 API was used to execute the injected payload in the identified process?
    > CreateRemoteThread
    - 
7. The injection method used by the attacker executes before the main() function is called. Which Win32 API is responsible for terminating the program before main() runs?
    > ExitProcess
    - 