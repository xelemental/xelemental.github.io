---
title:  "SpockStealer: Technical analysis of a Golang-based info stealer."
layout: post
categories: malware-analysis
---


## Table Of Contents

- Background.
- Stealer Analysis
    - Metadata
    - File Information.
    - Analysis of the stealer using IDA-Freeware.
    - Features of the malware.
    - Open Source packages used.
- Infrastructure Analysis.
- YARA Rule.
- MITRE ATT&CK.
- Summary.
- Resources.



## Background.

Recently, while I was browsing X previously known as Twitter, I stumbled upon a tweet or post by a fellow security researcher
[Yogesh Londhe](https://twitter.com/suyog41) which mentioned an uncommon stealer name, which I had never heard of, also known as Spock Stealer.

With the rise of modern compiled languages and the constant influx of the notion that malicious software written in languages like Go or Rust is cumbersome to analyze and dissect, coupled with the oversaturation of the stealer market, it seems like every aspiring programmer's go-to learning project is developing a stealer. Well, it does be like that sometimes. If you doubt this claim, I invite you to search the keyword 'Stealer' on GitHub, Telegram, and popular forums.

Initially, I thought Spock Stealer might bring something innovative in terms of functionality and overall quality. Unfortunately, I was disappointed to discover that it is just another basic stealer developed in Go. As an analyst, I'm unaware of the infection vector of this stealer, but I must commend the author for not using a precompiled GitHub project as part of the campaign, unlike this [threat actor](https://xelemental.github.io/Golang-based-credential-stealer-targets-Indian-Airforce-Officials/).

Therefore, in this blog, I will walk through the technical aspects of this stealer and provide some YARA rules for fellow researchers.


## Stealer Analysis

In this section, we will perform some technical analysis on the stealer. 


### Metadata

SHA-256 : 89300678df750de360222d0cefbebb4291f30c5aec86c2cdaab32b0f09891e94.

Sample: Available [here](https://bazaar.abuse.ch/sample/89300678df750de360222d0cefbebb4291f30c5aec86c2cdaab32b0f09891e94).


### File Information.


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/8c584a7f-3420-46e0-8bfb-60fcdca98084)


File Name: `docx.exe`.

File Creation Time: `Unknown`.

Go-build ID: `"hyJI5wXtKgEwMeLZtwm5/SkRZinb1FBXW1ONyASbu/SlLnz5DZLKjb_mHyQtXl/tYupb-n1J34C4eBJLKsB"`

File Type: `Portable Executable 64`

VirusTotal Detection: `12/72` 



### Analysis of the stealer using IDA-Freeware.


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/85630011-b5b9-435b-bb8f-d709ed0f99af)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/a5470867-0205-44bf-856b-30096cc6b946)


Upon loading the file into IDA Freeware, we navigate to the `main_main` function. Then we can also see that there are various functions part of this main function like `getIpAddresses`, which enumerates the victim's IP Address, then we have `getHostname` which enumerates the hostname of the target machine, then we have  `getCurrentUser` which enumerates the current user name  and then we have `takeScreen` function which is responsible for capturing screenshots and then we have `getProcessList` & `getDesktopFiles` which are responsible for enumerating the list of processes running and the later is responsible for getting the lists of files in the Desktop folder of the target or victim device. 

Now, let us check out the individual functions one by one. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/9adf0d1d-4966-4097-b209-0e5bc5d19e11)

Upon exploring this function, we can see that this function is using a Golang package known as  [`net`](https://pkg.go.dev/net) used for network programming. Then we can see that the `net_InterfaceAddrs` function is being called, which is responsible for returning a slice of the `Addr` object which contains the unicast addresses.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/9ad23418-a174-4016-b59c-361ba049e463)

Then from the return object which is the slice, it then from the same net package `IPNet_net_Addr`, which checks if the returned slice contains IP addresses. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/e5c6efdf-f1c6-49a4-8887-1d44aa46a099)


Then, it checks if the IP Address is a loopback address using the `IP_IsLoopback` function. Then the IP Address is stored in a slice and then the loop continues, and finally the function returns the IP Address. Now, let us explore the next function. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/7022d963-67b9-49f0-8ccd-61c1c14d076f)

Upon exploring this function, we can see that this function uses a Golang package known as [`os`](https://pkg.go.dev/os#Hostname) which further uses a function known as `Hostname`. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/92fc7f6f-1feb-4cab-90d4-bd6612e8713a)

This function creates a slice which is used to store the returned value from the [`GetComputerNameEx`](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexa) API called in Golang, and finally, the slice is returned which contains the hostname. Now let us move ahead to the next function. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/3db5046b-4c4a-4526-893a-bc93e94d2cdf)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/ebb62ac3-e6a9-4a3e-8777-37426137c193)


Upon exploring this function, we can see that this function uses a Golang package known as [`os`](https://pkg.go.dev/os) which further uses a function known as [`Current`](https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/os/user/lookup.go;drc=185766de0ff2810ee018501addb1f58be2226856;l=21), to enumerate the current user. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/926d20c3-263d-440a-b274-3c55b41d39e7)


Upon enumerating the current user, it goes ahead and lists the groups from the enumerated user. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/9aed017b-8940-4473-a0e3-712d3ed5c841)

Now, upon enumerating the group, it goes ahead and enumerates the group ID. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/19e3343e-70e5-407d-aaf8-dcb4467f4d6c)


Now, once all the data is enumerated it saves the data into a slice object and finally returns from the function. The returned data from this function looks something like this `"groups":["S-1-5-32-544 = Administrators", "S-1-5-32-545 = Users", "S-1-5-21-2246122658-3693405117-2476756634-513 = None"]`. Thanks to Joe Sandbox.  Now, let us move ahead with the next function. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/51aa8962-b465-4a9a-8c9e-b40d8a892314)


Upon exploring this function, we can see that this function is responsible for capturing screenshots. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/3638fc18-c644-4fbb-a5dd-6d4092fd04e6)


As we can see this function uses an open source for capturing screenshots, initially, it uses `NumActiveDisplays` to enumerate the number of displays available. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/6f0bffee-9587-4788-aec9-4098a6c9aea1)


Then it gets the coordinates of the display which is it about to capture, and finally, it does capture it. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/67f7cb2d-614e-446e-8601-67d5e25e53d1)

Then, it encodes the data in PNG format. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/ec8b9457-33ef-4e45-abf8-926b6e7e3c07)


Then, it goes ahead and converts the PNG data to base64 encoding, and stores it in a slice object, which is finally returned from this `getScreenshot` function.  Now, let us move ahead to the next function. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/3fdf1cf5-3776-407b-ad0c-8238ef45b1fe)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/72055331-d6a0-4c7e-b003-87f13014fcf7)



Upon, looking into the function, we can see that the function is using [`gopsutil`](https://github.com/shirou/gopsutil/tree/master/process) to enumerate the running process in the target machine, and finally the data is tored in a slice object, which is returned. 










