# Jugglin

## Speech
```
Forela Corporation heavily depends on the utilisation of the Windows Subsystem for Linux (WSL), and currently, threat actors are leveraging this feature, taking advantage of its elusive nature that makes it difficult for defenders to detect. In response, the red team at Forela has executed a range of commands using WSL2 and shared API logs for analysis.
```

## Analysis

## Questions
1. What was the initial command executed by the insider?
    > whoami
2. Which string function can be intercepted to monitor keystrokes by an insider?
    > RtlUnicodeToUTF8N, WideCharToMultiByte
3. Which Linux distribution the insider was interacting with?
    > kali
4. Which file did the insider access in order to read its contents?
    > flag.txt
5. Submit the first flag.
    > HOOK_tH1$_apI_R7lUNIcoDet0utf8N
6. Which PowerShell module did the insider utilize to extract data from their machine?
    > Invoke-WebRequest
7. Which string function can be intercepted to monitor the usage of Windows tools via WSL by an insider?
    > RtlUTF8ToUnicodeN
8. The insider has also accessed 'confidential.txt'. Please provide the second flag for submission.
    > H0ok_ThIS_@PI_rtlutf8TounICOD3N
9. Which command executed by the attacker resulted in a 'not found' response?
    > lsassy
10. Which link was utilized to download the 'lsassy' binary?
    > http://3.6.165.8/lsassy
11. What is the SHA1 hash of victim 'user' ?
    > e8f97fba9104d1ea5047948e6dfb67facd9f5b73
12. When an attacker utilizes WSL2, which WIN32 API would you intercept to monitor its behavior?
    > WriteFile