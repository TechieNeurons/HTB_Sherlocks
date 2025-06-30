# Loggy

## Speech
```
Janice from accounting is beside herself! She was contacted by the SOC to tell her that her work credentials were found on the dark web by the threat intel team. We managed to recover some files from her machine and sent them to the our REM analyst.
```

## Questions
1. What is the SHA-256 hash of this malware binary?
    > 6acd8a362def62034cbd011e6632ba5120196e2011c83dc6045fcb28b590457c
    - sha256sum
2. What programming language (and version) is this malware written in?
    > Golang 1.22.3
    - open ghidra
3. There are multiple GitHub repos referenced in the static strings. Which GitHub repo would be most likely suggest the ability of this malware to exfiltrate data?
    > github.com/jlaffaye/ftp
    - open in ghidra or strings | grep github
4. What dependency, expressed as a GitHub repo, supports Janice’s assertion that she thought she downloaded something that can just take screenshots?
    > github.com/kbinani/screenshot
    - idem
5. Which function call suggests that the malware produces a file after execution?
    > WriteFile
    - 
6. You observe that the malware is exfiltrating data over FTP. What is the domain it is exfiltrating data to?
    > gotthem.htb
    - need the shitty plugin
7. What are the threat actor’s credentials?
    > NottaHacker:Cle@rtextP@ssword
    - f*cking plugin
8. What file keeps getting written to disk?
    > keylog.txt
    - 
9. When Janice changed her password, this was captured in a file. What is Janice's username and password?
    > janice:Password123
    - 
10. What app did Janice have open the last time she ran the "screenshot app"?
    > Solitaire
    - 