---
title:  "GoStealer: Golang-based credential stealer targets Indian Airforce Officials."
layout: post
categories: malware-analysis
---

## Table Of Contents

- Background
- Malicious ISO Analysis
    - Metadata
    - What is this ISO about?
    - Extracting malicious artefacts.
    - Analyzing malicious artefacts.
    - What is the decoy document about?
    - Overview.
- Stealer Analysis
    - Metadata
    - File Information.
    - Analysis of the stealer using IDA-Freeware.
    - Features of the malware.
    - Open Source packages used.
    - YARA Rule.
    - Overview.
 - Infrastructure Analysis 
    - Finding Slack Channel using SlackPirate.
    - Overview.
 - MITRE ATT&CK.
 - Summary
 - Resources

## Background

![Infection-Chain](https://github.com/xelemental/xelemental.github.io/assets/49472311/b34b3986-3854-4ab4-a553-1d3be9eedfa2)



This blog delves into the analysis of a stealer written in the  modern-day compiled language, Golang. Luckily, I came across a [tweet](https://twitter.com/Cuser07/status/1745356248307159163) by a fellow security researcher who goes by the alias [@Cuser07](https://twitter.com/Cuser07/), mentioning an intriguing ISO that has been uploaded from India. In addition to examining the stealer, this blog will concentrate on extracting malicious content from the ISO and implementing YARA Rules for hunting.


## Malicious ISO Analysis

### Metadata

SHA-256 : 4fa0e396cda9578143ad90ff03702a3b9c796c657f3bdaaf851ea79cb46b86d7

Sample: Available [here.](https://bazaar.abuse.ch/sample/4fa0e396cda9578143ad90ff03702a3b9c796c657f3bdaaf851ea79cb46b86d7/)


### What is this ISO about?

Before we proceed with the extraction and analysis of this malicious ISO, could you help us gain a better understanding of the ISO and its significance with a moderate level of confidence?

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/57281d21-4870-492c-8816-da8dcbad4b04)


Recently, the [Indian Government issued a tender](https://www.indiatoday.in/india/story/indian-air-force-tender-to-hal-for-su-30-mki-fighter-jets-2465944-2023-11-22) to Hindustan Aeronautics Limited, also known as HAL, for the procurement of 12 Sukhoi-30 MKI, a variant of superior fighter jets enhancing the Indian Air Force's arsenal. These jets are sourced from JSC Sukhoi Company, an aircraft manufacturer based in Moscow. As per the newspaper article, HAL was required to respond to the tender by the end of December.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/41c2e83e-145f-487f-a69c-3edaec1b0b30)

Now, we observe that the sample was initially submitted to VT on the 9th of January 2024. Therefore, with a moderate level of confidence, we can infer that the unknown threat actor is impersonating the Sukhoi Company, attempting to deceive Air Force officials into believing that this ISO contains sensitive information.

### Extracting malicious artefacts.

There are a lot of tools on the web, like the famous [ISODump](https://isc.sans.edu/diary/isodumppy+and+Malicious+ISO+Files/25134) by Didier Stevens. But here will use simple 7z to extract contents from the ISO file. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/44170fe5-03a4-4ae1-bf21-0ae55e0ca756)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/53b5f78b-5e35-4c59-86d5-dc9ea5ea2b5f)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/7a651318-01f7-4901-b6fa-52813d2411b9)

As we can see upon extraction, there are three files one of them is the LNK file, and a small `.temp` file is created, which contains an executable named `.tmp.exe` and a decoy PDF known as `sample.PDF`. In the next section, we will focus on the analysis of these files. 


### Analyzing malicious artefacts. 

Let us start with the analysis of the LNK sample. For parsing the malicious LNK file, we will be using [LnkParser](https://github.com/silascutler/LnkParse). 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/7eeb2e0b-33cc-4ddb-8636-1d410ad712db)

A small dilemma arises while analyzing the LNK file. The creation timestamp dates back to the 14th Of November, and the accessed timestamp is on the 9th of December 2023. Now, with a moderate level of confidence, we can confirm that this campaign was staged during the same time as the tender initiated by the Government of India to HAL.

Next, examining the `commandLineArgument` parameter reveals that it contains the value to start the `.tmp.exe` executable in the background using `cmd.exe` and then launch the decoy document `sample.pdf` in the foreground.

Now, we will examine the `.tmp.exe` executable extracted from the iso file. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/34559ecc-f1dd-40b6-ab45-3a471effb65f)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/32876979-c577-4052-a3d9-64e52f17977e)


Initially, we will use tools like Detect It Easy or DIE to determine if the file has been packed and to identify certain basic characteristics of the file, such as suspicious strings. After examining the strings and the entropy of this binary, we can conclude that it is a Go-compiled binary. Lastly, we will investigate the decoy document.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/a67236db-d061-4c17-aa87-28b004301135)


This decoy document is entirely unrelated to the original ISO and pertains to the **premature retirement** of Air Force Personnel, also the date of the publishing of this document is 24th June 2023, Therefore, we can conclude this with a medium level of confidence that this PDF acts as a bait and as a decoy unrelated to the current subject matter of Sukhoi aircraft. In the next phase, we will delve deeper into the decoy document to understand its contents.

### What is the decoy document about? 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/880b5c23-bcd5-44d3-b425-7695a2d56e04)

This decoy PDF provides guidelines for Air Force Personnel on availing Premature Retirement from the Air Force. The various appendices of this 16-page document guide the reader through the DOs and DON'Ts, as well as various criteria and supporting documents required for completing the application. These documents include items such as NOC (No Objection Certificate) and Certificate Of Service. Overall, this PDF ensures a thorough and standardized guide and information for officers at the Air Force Headquarters. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/49d4e72d-d3b8-4d52-b86d-0e011b6ee9a5)


An interesting matter of fact is that this document mentions [Air Marshal Arvind Kumar Nagalia](https://www.bharat-rakshak.com/IAF/Database/11633), as an AOP also known as Air Officer-in-Charge Personnel, whereas the current AOP of Air Force is Air Marshal Nagesh Kapoor, as per the recent [Press Release](https://pib.gov.in/PressReleaseIframePage.aspx?PRID=1954109). 

### Overview.

After analysing all the artefacts extracted from this ISO, we can confirm that the threat actor used the Sukhoi deal as bait delivering a stealer programmed in Golang. 


## Stealer Analysis

### Metadata

SHA-256 : 8de4300dc3b969d9e039a9b42ce4cb4e8a200046c14675b216cceaf945734e1f

Sample: Available [here.](https://bazaar.abuse.ch/sample/8de4300dc3b969d9e039a9b42ce4cb4e8a200046c14675b216cceaf945734e1f)

### File Information

File Name: `.tmp.exe` 

File Creation Time: `21 December 2023` 

File Type: `Portable Executable 64` 

VirusTotal Detection: `30/69` 


### Analysis of the stealer using IDA-Freeware.


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/1a3a6a09-30fe-4b08-add6-6898cc04a036)


Let us load the sample in IDA-Freeware, and once we are done loading the sample and the autoanalysis has finished, we start our analysis from the `main_main` function as this is the actual main function unlike simple binaries written in C++. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/591889c9-6194-44b8-8c76-5a3b76510624)

After scrolling the function graph, we encounter the first interesting function among a lot in this binary known as `Supvlhopmb`, let us dig inside the function and find out the working of this function along with the return value. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/7c73a26c-c7ba-4ed0-8ef9-93d7b73ea4a7)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/363c3cb7-2fd4-4df9-bbf0-3aac3c990990)

So, this function creates or opens the `Temp` directory and after that creates a text file known as `Vihvaivlxd.txt` and returns the file info. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/f5b45b8f-d002-40b2-8501-a27d60f67efc)

The next, interesting function we encounter is known as `Zkjajhldz`, let us dig inside this function and find out the working and return value of this function. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/21c1e354-8fe5-482b-87a0-6628eba6a33e)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/43ddbf90-5e32-4605-bcf8-28d65c74b181)

We can see in this function, that the DLLs `ntdll`, `kernel32.dll` & `kernelbase.dll` are being passed to a [slice](https://www.geeksforgeeks.org/slices-in-golang/) which is being used for a function `FullUnhook`. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/c0b17b1f-a806-471c-a9de-e10bcc96cabd)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/876ff201-f2b5-48ad-85d7-05e70a2317ab)

Upon diving into the `github_com_timwhitez_Doge_Gabh_pkg_Gabh_FullUnhook` function, we can see that it takes the DLL Slice/array name, as its parameter and upon a little browsing on GitHub, we can finally find this repository known as [Doge-Gabh](https://github.com/timwhitez/Doge-Gabh/blob/main/pkg/Gabh/unhook.go) which contains proof of concepts of various red-team techniques, and from them, the current code uses the DLL Unhooking technique to avoid userland API hooking. Therefore, we can conclude that the function performs DLL Unhooking. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/4dc91ea6-8352-444e-af64-b13e6ddf89c4)

Moving ahead to the next interesting function known as `Wyoaitjk`, let us dive in and check the working of the function. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/6646f66a-09cf-41e5-aa13-bcf0b167bca5)

Upon opening the function, we were greeted with another interesting function known as `Jruqsw()`, now let us dive inside that function. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/f2694621-780d-4f1b-87c3-667aefc8e4e2)

Here, we can see that the function, we were greeted with is exactly similar to an open-source project known as [Go-Stealer](https://github.com/idfp/go-stealer). 


Now, as we can see that the code is completely the same as the open source project, let us rename the functions for better understanding and continue our analysis. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/1cb4b84a-b23e-4e25-b857-7c0b9482fee7)

Once, the `profiles` folder is enumerated from the `APPDATA` environment variable and returns the path, it then moves ahead stealing the cookie, let us rename the next function as `FireFoxStealCookies` . 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/0d49368c-b563-464e-9350-b7a6c110eb32)

Inside, StealCooking function, we have another function which basically performs dumping the cookies from the `sqlite` database located at `\cookies` path. The function takes the path as argument. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/a6bf90b4-24d6-4941-8c8f-26cc272934f5)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/2befd68e-d05b-4788-9d6e-61e1bd7c24cc)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/01ba1ea6-1e0f-468e-8221-c22eae593b88)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/d91e88b3-c43d-4012-b456-bec7444fe343)


Now, once it is done, dumping the cookies, it then goes ahead to crack the passwords, this time we encounter a function `Hhyvpjr` , let us explore the function. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/fad2732a-170a-4093-a914-d83b23908085)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/f334ebd0-7685-4beb-99b1-2d37a7ec3b20)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/ad1ceacd-f62a-47dc-bc58-d9edf60cde40)

Next, in the same function the login data of the firefox which is to be stolen, is loaded using a function, and for better readability, I have named it `LoadLoginsData` , it converts the JSON into an array using `Unmarshal` funtion in golang.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/67277cf3-4af8-4a1f-84c6-9d4dcf9b8b4f)

Now, once the logins data is harvested from the JSON file, the code decrypts the username & password using `3DES` which takes the `key` , `IV` and the `ciphertext` as parameters and returns the plain text. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/8eefc5c7-eb04-4ecf-a800-0b4070baf90d)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/f5ad5891-1676-4c70-b7e9-1d52c9a0f98c)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/47baa54a-92e8-488c-ab7d-153e6cd25995)

Once the entire process is complete, it returns all the credentials, and finally we are done with the firefox credential section. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/675df82b-3ada-4688-9160-254e31845004)

Then, the content returned from the FireFox Stealer function is saved into another variable, where XOR operation is performed on the plaintext. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/f0ca552b-5724-4beb-b17d-5ae526ce5d83)

Next, it uses an open source re-written version of `PSUITL` in golang to kill the process, here it is Firefox.  You can find the project [here](https://github.com/shirou/gopsutil/blob/master/process/process_windows.go).

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/d21048ec-6d9a-44fd-9d69-bd2c9031dcb3)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/51cfc4a7-7dfd-470f-b827-c26c4741b826)


Similarly, just like of the firefox, the stealer does the same for Chrome Browser, which is a pure copy paste from the same project, can be found [here](https://github.com/idfp/go-stealer/blob/main/chrome.go) which involves dumping cookies, cracking login data. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/e4330a74-213d-44d0-9fde-828288ba082c)

Now, once the credentials are stolen, the stealer then proceeds to upload the content using Slack package for file uploading.Let us explore the workings of this function.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/df4083d5-cbb6-4718-8343-51a5c33a7580)

Initially, this function does some channel ID setup for sending the target files into a certain channel.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/19318619-c609-49e1-8e39-83790697d03d)

Them it sets the `params` structure with channel info and file details. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/00a2cf35-9798-4efe-979c-2caa8118401b)

Now, after doing the initial setup of various structures and contexts it passes the `params.File.str` to another function `Njuypus` . Let us explore the function. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/f99aa40a-991f-486f-970f-8312939cbe0e)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/1ee0207e-ca32-4430-a99b-3dbbed70f047)

This function performs a new token initialization using the `New` Method from the [Slack Package](https://pkg.go.dev/github.com/eaneto/notify/service/slack#New) and uploads the file to the specific channel using this token. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/94ba448d-ea5d-47b5-bc37-3d8cf3a96d28)

Then the next function uses `GetLogicalDrives` API from `kernel32.dll` to enumerate the available drives in the infected machine. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/351588df-7c01-4631-9bd4-1cb3b81386e1)

The last function uses the `token_initialization_file_upload` function & fixing file names to upload the files to Slack C2 using the slack bot. 

###  Features of the malware.

- DLL Unhooking for avoiding Userland API Hooking.
- Firefox & Chrome credential stealing.
- Using Slack C2.
- Enumeration of Logical Drives.


### Open Source packages used.

There are some notable packages used :

- `github.com/slack-go/slack@v0.12.3/`
- `github.com/go-ole/go-ole@v1.2.6/`
- `github.com/yusufpapurcu/wmi@v1.2.3/`
- `github.com/binject/debug@v0.0.0-20211007083345-9605c99179ee/`
- `github.com/timwhitez/doge-gabh@v1.9.3/`
- `https://github.com/idfp/go-stealer/`
- `https://github.com/gorilla/websocket`
- `https://github.com/zavla/dpapi`
- `https://github.com/shirou/gopsutil/`



### YARA Rule

I am not quite better at writing YARA Rules, but here I have added a very simple YARA Rule, to detect specific fragments of the binary, if you find any issues or find this rule ugly, please reach me out. Thanks! 

```yara
rule dogesteal {
    meta:
       author = "Elemental X"
       description = "Yara rule for detecting malicious gostealer binary"
       link = "hxxps://github.com/idfp/go-stealer/"
       hash = "8de4300dc3b969d9e039a9b42ce4cb4e8a200046c14675b216cceaf945734e1f"
       date = "2024-01-17"
    strings:
        //DLL Unhooking Doge-Gabh
        $s1 = { 48 8B 94 24 A8 00 00 00 8B 52 1C 48 03 50 10 48 89 54 24 50 }
        //DB Query Context
        $s2 = { BE 29 00 00 00 45 31 C0 45 31 C9 4D 89 CA E8 D1 B5 D6 FF 48 85 DB }
        //Calling XOR Encoding function
        $s3 = { BE 29 00 00 00 45 31 C0 45 31 C9 4D 89 CA E8 D1 B5 D6 FF 48 85 DB }
        //Token Initialization for Slack Channel
        $s4 = { 48 8B 05 83 97 54 00 48 8B 1D 84 97 54 00 31 C9 31 FF 48 89 FE E8 90 25 FA FF }
        //PDB Path
        $s5 = "E:/development/go-stealer/obfuscated/"
        //Enumerate Logical Drives
        $s6 = { BB 0C 00 00 00 E8 B2 BF CE FF 48 8D 1D 5D D8 21 00 B9 10 00 00 00 E8 E1 B8 CE FF }
        // Github Link
        $s7 = "github.com/idfp/go-stealer/"

    condition:
        // Detect if it a PE File and detects all opcodes 
        uint16(0) == 0x5A4D and 6 of them

  }
```

### Overview 

This stealer as we saw in most part of the analysis above is based on open source red team project, and most of the malicious code is inherited from the go-stealer project developed by an Indonesian security researcher. An interesting matter of fact looking upon the strings section of the binary is, there are lot of files which are not uploaded on the web, performing credential stealing for Brave Browser & Microsoft Edge. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/9d484322-a570-4135-a913-9dbe17ebfdca)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/7e1ae219-d8ac-491b-a1c4-5b3a6114fb80)


The highlighted piece of code is not present on the github project. Th author also mentions that they have no interest for deving support for Edge browser as this is just a Proof Of Concept.


## Infrastructure Analysis 

### Finding Slack Channel using SlackPirate.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/3882f216-3399-4c8f-bca5-8e1c02f51ecf)


As, this binary is using Slack as its command and control(C2) , upon the very look into the tweet, I encountered a fellow researcher known as [ddash](https://twitter.com/ddash_ct) tweeted about the authetication token `xoxb-6379011443682-6391721548145-3wbY7GyxHj9Ksw29pvLmqpuP` along with channel ID `C06B22AUJF7`, which even I discovered upon little debugging. Therefore, we will be using a tool known as [SlackPirate](https://github.com/emtunc/SlackPirate) to enumerate information about the channel. 

Before jumping to the phase of analysis, it is always better to know that there are four type of tokens in the Slack API.

- `xoxp-<token_here>` : User Tokens
- `xoxb-<token_here>` : Bot Tokens
- `xapp-<token_here>` : App-level Tokens
- Configuration Tokens.
  
Now, we will install SlackPirate from Github, and after installation, we will pass the bot token to the python script.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/cfa943bb-489a-4216-8a42-7ba2a0bfdf59)

Well, the tool did break down due to some issues, but thanks to it, we could manage to get the slack group's URL & the name of the bot or the user.

### Overview

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/0497f57e-edbd-4344-bc69-6cd37847fec3)


Thanks to SlackPirate, we could get little info about the slack group, and upon browsing the link, we can see that this group is a valid one. 


## MITRE ATT&CK.

T1204.002 : User-Execution - Malicious File.
T1562.001 : Defense Evasion - Disable or Modify Tools
T1555.003 : Credential Access - Credentials from Web Browser
T1489 : Service Stop
T1573.001 : Command and Control - Encrypted channel
T1083 : File and Directory Discovery
T1102: Command and Control - Web Service 


## Summary

Upon doing initial triage of the binary and technical analysis along with looking for the slack c2, we can comprehend that the campaign started during the times of announcement of the Sukhoi Deal around November-December, and the unknown threat actor uses an open source stealer known as Go-Stealer with TimWhite's POC of DLL Unhooking to avoid detection and then stealing chrome and firefox credentials and exfiltrate the data to a slack group known as `tucker-group` with the username of the bot being `super-service` as per the tool SlackPirate. 


## Resources

- Golang Official Website.
- Github[TimWhite]
- Github[Go-Stealer]
- Times Of India
- LnkParser.
- IredTeam.
- Slack Docs
- Slack Docs - Go Package
- SlackPirate.
- MITRE ATT&CK Framework
- MalwareBazaar
