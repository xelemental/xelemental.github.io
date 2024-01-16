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
    - Overview of the Stealer.
 - Infrastructure Analysis 
    - Finding Slack Channel using SlackPirate.
    - Overview of the Slack C2.
 - MITRE ATT&CK Mapping.
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


### Analysis of the stealer using IDA-Freeware & x64dbg.


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



