---
title:  "Looking into Wondershare Repairit DLL Hijacking issue"
layout: post
categories: malware-analysis
---


## Table Of Contents


- Background.
- DLL Hijacking.
- So why Wondershare ?
  - Identifying the issue of loading.
  - Crafting a malicious DLL.
  - Getting a callback.
- What's next?
- What else Wondershare?
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

