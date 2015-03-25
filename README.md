# dll_hijack_detect
Detects DLL hijacking in running processes on Windows systems

Usage: dll_hijack_detect.exe [/unsigned] [/verbose]

Optional parameters:
/unsigned - Only flags DLLs where at least one of them is unsigned
/verbose - Show all where DLLs are found in multiple search order locations regardless of whether the one loaded is one of them (expect false positives!)

You also get a couple of files to test the tool (look in the demo folder)
dll_hijack_demo.exe and dll_hijack_demo_dll.dll

If you want to see the demo in action, there is a youtube video:
https://www.youtube.com/watch?v=zkYAe8-wzfg

The program does the following:

1.Iterate through each running process on the system, identifying all the DLLs which they have loaded
2.For each DLL, inspect all the locations where a malicious DLL could be placed
3.If a DLL with the same name appears in multiple locations in the search order, perform an analysis based on which location is currently loaded and highlight the possibility of a hijack to the user

Additionally: Check each DLL to see whether it has been digitally signed, and give the user the option to ignore all signed DLLs
During testing I have found that DLL hijacking isn't always malicious, infact there are a whole bunch of digitally signed libraries which sit in the base directory of an application (perhaps they act differently to their generic counterparts?).

Accordingly, in order to reduce the amount of noise returned by the tool, I implemented the '/unsigned' parameter, which I would recommend you use the first time you run it. This ignores cases where both the DLL which has actually been loaded, and others found in the search order are all signed (and therefore, more likely to be legit) - if you want to dig deep, feel free to leave this off

SANS article on subject:
http://blogs.sans.org/computer-forensics/2015/03/25/detecting-dll-hijacking-on-windows/

Follow me on Twitter: @CyberKramer
