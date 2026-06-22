1. During execution, the malware initializes the COM library on its main thread. Based on the imported functions, which DLL is responsible for providing this functionality?
	> Ole32.dll
	- Open in PEStudio
2. Which GUID is used by the binary to instantiate the object containing the data and code for execution?
	> dabcd999-1234-4567-89ab-1234567890ff
	- Open in ghidra
	- From the previous question we know it's a COM application so let's look at the import link to that, to the DLL find previously
	- Looking at the ref a these imports we find CoCreateInstance which take a GUID
3. Which .NET framework feature is the attacker using to bridge calls between a managed .NET class and an unmanaged native binary?
	> COM Interop
	- **COM Interop** is the .NET feature that allows **managed .NET code** and **unmanaged COM components** to work together. (thanks chatgpt)
4. Which Opcode in the disassembly is responsible for calling the first function from the managed code?
	> FF 50 68
	- In analysis check all or doesn't appear
5. Identify the multiplication and addition constants used by the binary's key generation algorithm for decryption.
	> 7, 42h
	- ...
6. Which Opcode in the disassembly is responsible for calling the decryption logic from the managed code?
	> FF 50 58
	- ...
7. Which Win32 API is being utilized by the binary to resolve the killswitch domain name?
	> getaddrinfo
	- We have a string "kill switch triggered"
8. Which network-related API does the binary use to gather details about each shared resource on a server?
	> NetShareEnum
	- ...
9. Which Opcode is responsible for running the encrypted payload?
	> ff 50 60
	- ...
10. Identify the killswitch domain name the binary attempts to resolve.
	> _k1v7-echosim.net_
	- ...