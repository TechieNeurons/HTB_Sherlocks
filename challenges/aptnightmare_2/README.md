## Speech
> Upon completing the server recovery process, the IR team uncovered a labyrinth of persistent traffic, surreptitious communications, and resilient processes that eluded our termination efforts. It's evident that the incident's scope surpasses the initial breach of our servers and clients. As a forensic investigation expert, can you illuminate the shadows concealing these clandestine activities?

## Questions
1. What is the IP and port the attacker used for the reverse shell?
    > 10.0.2.6:443

    - `python /opt/volatility2/vol.py -f dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_netstat` to see all the connection, it's a reverse shell so the connection must be ESTABLISHED (not a listening port nor a closed one)
    - launch by bash PID 3633

1. What was the PPID of the malicious reverse shell connection?
    > 3632

    - psxview

1. Provide the name of the malicious kernel module.
    > nfentlink

    - I start with `linux_lsmod` but nothing weird... So I used `linux_check_modules` which find me this one, rootkits try to hide themselves from the module list but they can't hide from everything so we can find them with the second command, which look at `/sys/modules`

4. What time was the module loaded?

    > 2024-05-01 20:42:57

    - after getting the list of all files present in memory I did `cat all_files| grep syslog` then recover the syslog file with : `linux_find_file -i 0xffff98ea5a730528 -O syslog`

    - And we can find when the module is loaded in the syslog with : `strings syslog | grep nfent`

5. What is the full path and name of the malicious kernel module file?

    > /lib/modules/5.3.0-70-generic/kernel/drivers/net/nfnetlink.ko

    - `python /opt/volatility2/vol.py -f dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_find_file -L > all_files` I list all the cached file in the memory and store the result in a file, then I filter on the legitimate module name to see the legitimate one and the malware one `cat all_files| grep -i "nfnetlink"`

6. Whats the MD5 hash of the malicious kernel module file?

    > 35bd8e64b021b862a0e650b13e0a57f7

    - I dump the file with : `python /opt/volatility2/vol.py -f dump.mem --profile=LinuxUbuntu_5_3_0-70-generic_profilex64 linux_find_file -i 0xffff98ea266b5a68 -O bad_module.ko` and then md5sum it

7. What is the full path and name of the legitimate kernel module file?

    > /lib/modules/5.3.0-70-generic/kernel/net/netfilter/nfnetlink.ko

    - Same as question 5

8. What is the single character difference in the author value between the legitimate and malicious modules?

    > i

    - when a kernel module is created some metadata are added, things like the author, a description, etc. we can get them with the command `modinfo ./bad_module.ko`, a "i" is missing in the mail of the author

9. What is the name of initialization function of the malicious kernel module?

    > nfnetlink_init

    - I opened the file in Ghidra, in the `Symbol Tree` I find the `init_module()` function (it's the function which tell what function to launch when the module is loaded)

    - In this function we have this :

    ![init_module function](../img/aptnightmare2/00_init_module.png)

    - We see the execution of the reverse shell

    - to find the name we look at the `Listing` panel which tell us that init_module also as the name `nfnetlink_init` (we can see it in the labels of the symbol tree)

10. There is a function for hooking syscalls. What is the last syscall from the table?

    > __x64_sys_kill

    - I opened the module in IDA and after going in the init function I double click the sys_call_table reference

11. What signal number is used to hide the process ID (PID) of a running process when sending it?

    > 64

    - made some research online, asked perplexity is good too

    - The idea is when a "sys_kill()" is called (64) the rootkit intercept it and