What is the name of the malware family associated with the provided file?
Demodex
```
Was on virustotal no anymore
must do the first salinebreeze to look at the correct trendmicro blogpost
```

What .NET cryptographic class is used to perform decryption in the script?
System.Security.Cryptography.AesManaged
```
The first base64 can't be decoded (crypted)
The second base64 is this aes call
```

The key to decrypt the script must be entered on the command line when running the ps1. What variable holds the key?
$k
```
The AES managed object is stored in $o then the keysize is defined
Then $o.key become equal to $k which is equal to $args[0] so $k contain the key
```

What is the key required to decrypt the base64 encoded data?
password@123
```
Must be find online, reading the blog from the previous challenge
```

After decrypting the initial payload, a new PowerShell script assigns a value to the variable $cregvalue. What is that value?
midihelp
```
I modified the script :

# [string] $k=$args[0].ToString().padright(32,'0');
$k="password@123".ToString().padright(32,'0');
# $o=New-Object([System.Text.Encoding]::UTF8.GetString( [System.Convert]::FromBase64String("U3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeS5BZXNNYW5hZ2VkCg==")));
$o = [System.Security.Cryptography.Aes]::Create()
$o.KeySize=256;
$o.Key=[System.Text.Encoding]::UTF8.GetBytes($k);
$o.IV=@(0)*16;
$s0=$([System.Convert]::FromBase64String($s));
$s1=$o.CreateDecryptor().TransformFinalBlock($s0, 0, $s0.Length);
$result = [System.Text.Encoding]::UTF8.GetString($s1);
$result | Out-File -FilePath ".\decrypted.txt" -Encoding utf8
```

The variable $cregdata is associated with binary registry data stored as a base64 blob. What is the SHA-256 hash of the binary data?
3b1c251b0b37b57b755d4545a7dbbe4c29c15baeca4fc2841f82bc80ea877b66
```
In the script we have two cregdata, the first one seems useless because not used and then the second b64 cregdata is base64 decoded and stored in cregbin
I copy paste the b64 into cyberchef, decode and save to a file before sha256sum
```

What is the name of the malicious service?
MsMp4Hw
```
We see the command Get-Service which is used with the variable $svcname it's the name of the service
```

What is the full path of the malicious DLL?
C:\Windows\System32\msmp4dec.dll
```
After the svcname in a variable called svcdllpath
```

What registry path is used to associate the service group (msgroup) with the malicious service, so that it can be launched by svchost.exe?
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost
```
Search for $svcgroup and see where he is used
Here we find the answer: $ret = New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost" -Name $svcgroup
```

What is the line of code responsible for starting the malicious service after it has been installed?
Start-Service -name $svcname;
```
At the end of the script start the service
```

Which Windows API does the DLL import to obtain the local computer name?
GetComputerNameA,-,implicit,-,0x00000000,0x00000000,KERNEL32.dll
```
DLL written at line 45: try{[io.file]::WriteAllBytes( $([System.Environment]::ExpandEnvironmentVariables($svcdllpath)), $svchostbin);
Follow the svchostbin var to discover: try{$svchostbin=$([System.Convert]::FromBase64String($svchostdata));}catch{ Write-Output "E0" ; exit;};
Recover what is in the svchostdata and b64 decode and save to a file to get the DLL
Open the DLL in PEStudio and look at the import
```

In service DLLs, which function is typically responsible for being called by the Service Control Manager to initiate the service?
ServiceMain
```
Look at the export
```

Inside the previously named function, there are two calls to Sleep: one uses a variable argument and one uses a hard-coded delay. What is the value of the hard-coded delay (in milliseconds)?
10000
```
Open in ghidra, open symbol table, search for sleep
Look at the XREF, two in the ServiceMain function, go there
The second one is called with the number 0x2710 which is 10000
```
