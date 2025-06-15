# Operation Blackout 2025: Ghost Thread

#Windows #APIMonitor #process_injection #tls

## Speech
> Byte Doctor suspects the attacker used a process injection technique to run malicious code within a legitimate process, leaving minimal traces on the file system. The logs reveal Win32 API calls that hint at a specific injection method used in the attack. Your task is to analyze these logs using a tool called API Monitor to uncover the injection technique and identify which legitimate process was targeted.

## Analysis
Open the ampx64 file with APIMonitor, filter on the inject.exe and follow the API Call to get all the answer to how the process injection work

## Questions
1. What process injection technique did the attacker use?
    > Thread Local Storage
    - Open the ida file and see that the TLS callback function is used, which mean function launch before main, which mean using the TLS functionnality, also check MITRE process injection page
2. Which Win32 API was used to take snapshots of all processes and threads on the system?
    > CreateToolhelp32Snapshot
    - In APIMonitor we have multiple "strcmp" function, before all that this function is called to get snapshot of process 0 (the whole system)
3. Which process is the attacker's binary attempting to locate for payload injection?
    > notepad.exe
    - all the strcmp take notepad.exe and another process name
4. What is the process ID of the identified process?
    > 16224
    - At the end of the API Call of inject.exe we have this PID passed to other API call
5. What is the size of the shellcode?
    > 511
    - in the end of the API call, when the inject.exe use Windows API to create a new thread/inject data, the size is given in the calls
6. Which Win32 API was used to execute the injected payload in the identified process?
    > CreateRemoteThread
    - Windows API calls such as CreateRemoteThread, SuspendThread/SetThreadContext/ResumeThread, and those that can be used to modify memory within another process, such as VirtualAllocEx/WriteProcessMemory, may be used for this technique.
7. The injection method used by the attacker executes before the main() function is called. Which Win32 API is responsible for terminating the program before main() runs?
    > ExitProcess
    - The only API call to terminate a process