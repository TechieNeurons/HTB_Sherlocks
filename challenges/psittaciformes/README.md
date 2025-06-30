# Psittaciformes

## Speech
> Forela carry out penetration testing of their internal networks utilising an internal team within their security department. The security team have notes from tests in addition to company critical credentials. It seems their host may have been compromised. Please verify how this occurred using the retrospective collection provided.

## Analysis
1. After extracting we get this file : `catscale_parrot_20241223-2233.tar.gz` which is the result of the [catscale bash script](https://github.com/WithSecureLabs/LinuxCatScale)
2. After cloning the catscale repo we can use the `Extract-Cat-Scale.sh` script in order to get our file
3. From the text we know that the computer has been compromised and we must find how.
4. In *logs/who* we find only one username `johnspire`
5. In the User's file, we can check the bash history and see that he downloaded a weird github repo name `autoenum`, we can go on the repo and check the only script of the repo
6. In this script we can see a weird function named `do_wget_and_run` which seems to download a zip file and we can see the password here :
```
    part1="c3VwZXI="
    part2="aGFja2Vy"
    PASSWORD=$(echo "$part1$part2" | base64 -d) # Give superhacker
```

## Questions
1. What is the name of the repository utilized by the Pen Tester within Forela that resulted in the compromise of his host?
    > autoenum
    - 
2. What is the name of the malicious function within the script ran by the Pen Tester?
    > do_wget_and_run
    - 
3. What is the password of the zip file downloaded within the malicious function?
    > superhacker
    - 
4. What is the full URL of the file downloaded by the attacker?
    > https://www.dropbox.com/scl/fi/uw8oxug0jydibnorjvyl2/blob.zip?rlkey=zmbys0idnbab9qnl45xhqn257&st=v22geon6&dl=1
    - Just after the password, in the `FILE_URL` variable, just have to concatenate the two var f1 and f2
5. When did the attacker finally take out the real comments for the malicious function?
    > 2024-12-23 22:27:58
    - Clone the autoenum repo and check the logs and compare
6. The attacker changed the URL to download the file, what was it before the change?
    > https://www.dropbox.com/scl/fi/wu0lhwixtk2ap4nnbvv4a/blob.zip?rlkey=gmt8m9e7bd02obueh9q3voi5q&st=em7ud3pb&dl=1
    - Diff avec les précédents
7. What is the MITRE technique ID utilized by the attacker to persist?
    > T1053.003
    - Add to cron
8. What is the name of the technique relevant to the binary the attacker runs?
    > T1020
    - Download and execute the malware, it's a cryptominer