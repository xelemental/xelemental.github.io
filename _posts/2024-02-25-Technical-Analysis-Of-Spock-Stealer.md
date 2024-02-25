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

VirusTotal Detection: `9/72` 



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


Then, it checks that if the IP Address is a loopback address using the `IP_IsLoopback` function. Then the IP Address is stored in a slice and then the loop continues, and finally the function returns the IP Address. Now, let us explore the next function. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/7022d963-67b9-49f0-8ccd-61c1c14d076f)

Upon exploring this function, we can see that this function uses a Golang package known as [`os`](https://pkg.go.dev/os#Hostname) which further uses a function known as `Hostname`. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/92fc7f6f-1feb-4cab-90d4-bd6612e8713a)

This function creates a slice which is used to store the returned value from the [`GetComputerNameEx`](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexa) API called in Golang, and finally, the slice is returned which contains the hostname. Now let us move ahead to the next function. 






