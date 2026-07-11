1. `File` tell us nothing, `strings` is interesting but too much noise
2. `binwalk` is interesting and tell us that the firmware is made for running on ESP32 board, the first result of `binwalk` is the main program runs on the board

To solve use these links:
https://olof-astrand.medium.com/reverse-engineering-of-esp32-flash-dumps-with-ghidra-or-ida-pro-8c7c58871e68
https://github.com/tenable/esp32_image_parser
Two error to fix:
https://github.com/tenable/esp32_image_parser/issues/4
https://github.com/tenable/esp32_image_parser/pull/3/files#diff-1368b0240ab104b7443fb9d776e7c3372f4fb7e7ac8776fb7116f36fcc73f78e

## Sherlock Scenario

An attacker has gained access to the supply chain of StoreD and has successfully uploaded malicious firmware to an environmental sensor which has then attempted to connect to many hosts on the network. Your task is to reverse engineer the firmware to discover what the device tries to do.

## Questions
Task 1 - What WiFi network does the device connect to?
StoreD-Corporate
In ghidra (after converting the ESP32 image to ELF) follow the string wifi_setup (or similar function name), in the function setting up the function we see this string push on the stack before the wifi setup string

Task 2 - What was the WiFi password?
StoreD@2024
Same as before, this string is push just after the name of the wifi

Task 3 - What IP address do the temperature and pressure measurements get sent to?
10.137.244.155
From the wifi function go back to the function calling the wifi function, in this "main" function we see (at the end) three call to one function which add Task to the Core of the OS, these task are: udp_send_task, report_task, sensor_task
In the udp_send_task you can find this IP with multiple strings link to temperature, pressure, sensor, etc.

Task 4 - What is the name for the FreeRTOS task that performs the attack?
report_task
Only three task are created, from the three two get us to the same code, the third one is the one scanning the network and exploiting

Task 5 - How many FreeRTOS tasks does the application create (not including library functions)?
3
CF the two previous answer

Task 6 - What protocol is the payload attacking? Give the three letter acronym.
FTP
In the report_task we spot the exploitation payload, this payload start with USER which is a FTP command

Task 7 - What address does Buffer Overflow attack place in EIP?
0x7C885037
Take a look at the payload starting with USER, after the Bs is the new EIP value then some NOP and then the code to execute, the address before the NOP is the new EIP

Task 8 - To what IP does the attack send a reverse shell?
192.168.178.63
Create a launcher for the shellcode and execute in Windows to spot the address with procmon or wireshark
