---
title:  "Winver: Reverse-Engineering PatchWork APT's recent Golang implant."
layout: post
categories: reverse engineering
---


## Table Of Contents

- Background
- Overview of the implant.
    - Metadata.
    - Certificate.
    - Misc.
- Reverse Engineering the implant using IDA-Freeware - I
- Reverse Engineering the implant using IDA-Freeware - II
- Features & Capabilities of the implant.
- Maturity of the threat actor.
- Implants alignment with the common go-malware landscape.
- Limitations.
- Author's two cents.
- Resources.





## Background.

Recently, since I started publishing blogs once again in January 2024, I have come across a lot of samples written in Golang, be it generic stealers like the ones in my previous [blog posts](https://xelemental.github.io//), be it new stealers in the market, like [Planet Stealer](https://inquest.net/blog/around-we-go-planet-stealer-emerges/), then I did come across a demo or random ransomware which was in the wild, I cannot recall the name, while drafting this blog post. So, I have decided to throw my skill under the golang malware bus and check the calibre of my present skillset of analyzing Golang Malware. 

Well, recently in this process of hunting, I did come across a [tweet](https://twitter.com/suyog41/status/1765725837041824121) by fellow security researcher [Yogesh Londhe](https://twitter.com/suyog41), who posted about a fresh implant linked to PatchWork Threat group. Consequently, this blog will predominantly serve as a blog on the reverse-engineering side of things rather than a conventional malware analysis discourse.



## Overview of the implant.

In this section of the blog, we will focus on some basic analysis of the implant. Well, there is not much to the implant in terms of usage of external obfuscators & packing software, so I decided to limit the overview to three sections which are _Metadata_, the interesting _Certificate_ and a few _misc_ artefacts about the sample. Let us dive in. 



### Metadata.

SHA-256 : 01EA7197094B9ACD50605BDA611111EAA822230F81A3CAC4B47A2F9D01E146C1.

Sample: Available [here.](https://www.virustotal.com/gui/file/01ea7197094b9acd50605bda611111eaa822230f81a3cac4b47a2f9d01e146c1/detection)


### Certificate.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/236d999a-657f-4be4-861e-706c4674ed2a)

Well, it turns out that this certificate has been issued by an [IT Consulting company](https://codingcomputer.org/contacts/) based out of the United Kingdom, and the recent implants of PatchWork have been seen using the same certificate in the campaigns. So, for my defender friends out there, this can be a simple artefact. 


### Misc.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/73ff6f5d-6343-4d78-be0f-049fafdc3635)

Well, I was initially pretty much confused about the nomenclature of the implant which is `Apollo ` as per the security researchers tracking this threat group. Well, then it turns out the project path's name is Apollo. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/89bf38f2-aba3-451e-9346-4a82b35825d4)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/265ba517-0c8c-4dc7-9c95-73c3745af5f6)

Thanks to PEStudio, for these details. Pretty impressive tool as always, it mapped a few artefacts making it clearer and giving a clear overview of the sample. Now, in the next sections of the blog, we will use IDA-Freeware to reverse engineer the implant binary. 




##  Reverse Engineering the implant using IDA-Freeware - I

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/2a2f93b5-3c01-4dde-adb7-fcb65c23bd1b)

Well, as soon as we load the file in IDA-Freeware and post-autoanalysis, we have the actual `main` folder, which contains a bunch of interesting functions, well the reason am calling it a folder is because post-recent additions to IDA disassembler's capabilities allow, a bunch of functions to be scrutinized under a certain package like `os`, `http` etc. So, am lucky, that I do not have to hover around every function and find co-relations, saving me some time. 

And, as the number of functions is 20. We will cover the working of each function in this blog post by covering the initial ten functions, in this first part and the rest in the next section of blogs.


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/62a50e6f-90c4-44f4-abd0-a5e6e73a0d96)

Upon landing in the `main` folder, we are welcomed with the very first function `main_main`, which is the actual `main` function, which calls the other 19 functions. Let us now go ahead to the next function. If you want to understand, a bit in-depth about the `main` function, refer to this [blog post.](https://medium.com/@nishanmaharjan17/reversing-golang-binaries-part-1-c273b2ca5333)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/cb94935f-6004-4601-a0f1-320ccfbafa5a)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/299d6cf3-0c9b-4f77-8057-51b7e6c61b21)


Now, here we encounter a function named `setConsoleCodePage`, let us go through the workings of this function.  As we can see argument `65001` is being passed to the `setConsolePage` function. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/460bd613-a0cc-4667-9e6f-4855c0776e22)

Turns out that the code is using [`exec`](https://pkg.go.dev/os/exec) package from golang, to execute this command `cmd chcp /C` which will change the current code page to [`UTF-8`](https://ss64.com/nt/chcp.html) and immediately terminate the cmd window. That's the purpose of this function. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/c29522f1-9d0f-4098-b5a6-106216ad2261)

After moving ahead with the analysis of the code, we could see that a URL is mostly acting as a command & control server here.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/9925c2ce-93ec-48a5-96c6-afbf4c676758)

Then, we see another weird-looking string loaded into the `RAX` register just like the URL of the C2 had been loaded. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/58d5d323-06f6-4498-8356-80294a7aec52)


![Yogesh's tweet](https://github.com/xelemental/xelemental.github.io/assets/49472311/7ef0185f-8325-439b-8e4c-be725edb9fe2)


Again, a very similar pattern is being followed, thanks to Wireshark filters, we figured out that the weird-looking string `AGCXHMYAJVKDHBRACJNKHX` is the unique User-Agent, which will be used to send a simple `POST` or in layman terms for connecting back to the C2. Next, we have a function known as `sendPing`.


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/6f535ee8-57c7-41bc-87cb-4018ba185cc2)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/0cee2692-937b-49d7-839c-b4ac66ec3761)



Upon browsing, this `sendPing` function, we see that the implant is trying to enumerate the `UUID` of the target device using `wmic` and then later using these individual strings as arguments for `os_exec_Command` function, to run it. Just when the implant runs, a window `wmic.exe` pops up and quickly terminates. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/7d8f4104-4545-4c04-a8e4-448956d53827)

Then, the implant uses `os` package code from the Golang library, to enumerate the current username.


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/f7f1e965-712d-49a6-8fba-23aa6736f0a5)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/2bcd3e94-9465-413f-8a5f-d314ee77ae2d)


Then, we have another function known as `encryptRC4` which performs as per the nomenclature of the function and encrypts the enumerated data performed by those functions, which we just saw using the RC4 algorithm. Let us move ahead with the rest of the code.


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/690e157e-c955-4354-8ec1-12b1b99921e4)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/64f0226d-34b9-4e01-85fa-add6a37ea186)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/a6a296d5-c03a-45ba-b440-bd419b8f4193)


Here, we encounter another function known as `getHostName`. As, the name says it uses `hostname` function from the `os` package in Golang to enumerate the hostname and return it, later which gets encrypted using RC4.


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/025afa5b-a71a-4579-a12e-f5d3ce009ec0)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/26b3f98d-1166-4ef8-978a-791ed9264b0a)


Now, here we encounter another function known as `getExternalIPAndCountryCode` which enumerates the IP Address and then geolocates it using [IP-API](https://ip-api.com/) service and returns the data for exfiltration. Now, let us continue with the analysis of the rest of the functions in the next section.




## Reverse Engineering the implant using IDA-Freeware - II


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/dd8c5376-66f3-46f6-ac3f-2891d6984120)

Moving ahead, we encounter another function known as  `getWindowsVersion` let us explore the function. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/813974a6-43b9-4007-a3ae-f1c503823c6a)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/3a98f096-66b4-4d9f-ad9a-57e12322e6c2)


This function uses `golang_org_x_sys_windows_registry_OpenKey` to open the registry key, and then uses another golang function known as `golang_org_x_sys_windows_registry_Key_GetStringValue` to read the `ProductName` which helps the function to enumerate the current version of the Windows like for example `Microsoft Office Professional Plus 2010`. Once the product or version name is enumerated, it goes ahead and returns the value, which then is passed as a plaintext parameter to the `encryptRC4` function, which later encrypts it for exfiltration purposes.


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/bf6a00bc-270b-4987-96cb-258ce35de9a3)


Next, we encounter another function known as `getExecutablePath`, let us explore the function.


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/3271a8e9-522f-4964-b593-0e598dc3d2ce)


Then, we see that the function is using [`os_Executable`](https://go.dev/src/os/executable.go) a golang function to query the path which launched the executable, later then once the function returns the path, it uses another function from the file path module, known as [`Abs`](https://pkg.go.dev/path/filepath#Abs) which returns an absolute representation of the path. If the path is not absolute it will be joined with the current working directory to turn it into an absolute path. 

Therefore, it returns the absolute path of the implant, which launched it. 



![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/eaff4590-6eae-4a07-b483-17dc797d2905)


Next, we have another function, known as `main_getCurrentProcessID`, let us explore the function. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/83f98c79-c513-425a-a694-0ec7aa84439d)

We can see that the function is using the `getCurrentProcessId` function, from the windows [`syscall`](https://go.dev/src/syscall/syscall_windows.go) package to enumerate all the process IDs running in the current system, then uses a golang native function known as `FormatInt` which returns a string representation of the integer value, which is later returned by this function, and then this value is passed to `EncryptRC4` function to encrypt it which is to be exfiltrated. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/801d2ece-72ba-433b-871b-30f66f9fde26)


Next, we see a native golang function known as `GetEnv` whose function signature goes like `func Getenv(key string) string`, where the only argument key is the `PROCESSOR_ARCHITECTURE`. This returns the process architecture. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/26bbb80b-41a5-46b2-ae98-c07cfe1d007d)


Next, we encounter another function known as `sendHTTPRequest`. Let us explore the function. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/a1c56c1f-afb9-4c68-bfe2-4409e37cede6)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/eefde45f-7b37-4565-9603-dc5c5b188ee3)



As we dive into the function, we can see that here, it tries to send a `POST` request to the C2.


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/6fae2c5d-114d-4352-9fbd-849afc583f64)


Well, moving ahead with this function, we can see that this is sending a request, before the function returns we have another interesting function known as `checkCommand` , let us explore that function.
















