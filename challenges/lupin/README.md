Task 1 - What is the entropy value of the executable file?
> 6.41450
Only on DIE

Task 2 - What is the consistent filename used by the malware when replicating itself across different locations?
> syscrondvr.exe
Goes in "entry" function, we see:
```
    wsprintfW(local_83c,L"%s\\%s",local_a4c,u_syscrondvr.exe_00414324);
    BVar5 = CopyFileW((LPCWSTR)&psz_00415fc0,local_83c,0);
```

Task 3 - Following filename verification, which Win32 API does the binary use to enforce region-based execution constraints?
> GetLocaleInfoA
Check the IAT and search for the different API that can be used for that

Task 4 - The function at relative address 0x407680 makes a WinAPI call immediately before initiating the network request. Which WinAPI function does it call to ensure fresh data is retrieved from the C2 server?
> DeleteUrlCacheEntry
Go in the function

Task 5 - Samira noticed unusual behavior during the paste operation — what is the relative address of the function that is responsible for this strange activity?
> 0x405B90
In the IAT look for "clipboard" API, the open/close/get etc. are called in this function

Task 6 - Which Windows message, serves as the primary trigger for initiating the clipboard content?
> WM_DRAWCLIPBOARD
General question, could be this one or `WM_CLIPBOARDUPDATE`, to find the correct one I goes to the `SetClipboardViewer` and goes up we see he use param, when we follow the xref of the code taking us to this call we have multiple 0x308 (which correspond to WM_DRAWCLIPBOARD) before the call that take us to the set clipboard viewer 

Task 7 - What is the relative address of the function used to modify Samira's clipboard content by replacing it with new data?
> 0x404A60
The function `SetClipboardData` is in this function

Task 8 - A transaction was made from "jamilaaidos.eth"; what is the transaction hash associated with the user latest operation?
> 0xab2d474dad344da1e3b7ece6e7022c3295c52b176978337be82288a59e5a2a40
Goes on etherscan, search for the .eth go to the user and check the transactions but I see two more recent transaction

Task 9 - What specific multicast IP address is targeted by the SSDP M-SEARCH discovery probes?
> 239.255.255.250
Search for M-SEARCH in the strings

Task 10 - What standard UDP port number is used for the SSDP M-SEARCH discovery requests?
> 1900
Just before the IP find in the previous question, or search online, it's the normal port

Task 11 - What is the malware family associated with the malware?
> phorpiex
VirusTotal