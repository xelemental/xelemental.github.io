---
title:  "Lockkey: Technical analysis of a Golang-Ransomware."
layout: post
categories: malware-analysis
---



## Table Of Contents

- Background.
- Metadata.
- Basic Static Analysis.
- Looking into the code using IDA-Freeware.
- Capabilities.
- YARA Rule.
- MITRE ATT&CK.
- Author's two cents.
- Resources.


## Background 


![GOGiyM9WkAAnrXB](https://github.com/xelemental/xelemental.github.io/assets/49472311/ada9293d-4f82-4f38-8749-cdf4cb905055)


Recently, while I was browsing X(previously known as Twitter), I encountered a tweet by one of the malware researchers from the community, who is pretty well known for hunting malware samples, posted about a new ransomware variant known as [lockkey](https://x.com/siri_urz/status/1792893139398566179/), which is programmed in Golang. As I have enjoyed analyzing Golang-based malicious executables recently, I decided to give this new ransomware a go. So, this blog post will contain a technical analysis of the ransomware, its capabilities, and a YARA Rule and TTPs aligned with the MITRE Framework. 


## Metadata

SHA-256 : eb58cbfca307a9d3cfe718d772f7a53079db87bc8936023d6b7adb8cf7206711

Sample: Available [here](https://bazaar.abuse.ch/sample/eb58cbfca307a9d3cfe718d772f7a53079db87bc8936023d6b7adb8cf7206711/#intel).



## Basic Static Analysis.



![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/068cf6ec-456f-40c5-a3f5-80042cbf5097)


Once, we are done downloading the sample, we go ahead with loading the sample on Detect-It-Easy an initial triage binary analysis tool, which gives us confidence that this sample is programmed using Golang. Next, we go ahead and check for some artefacts.


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/0c031239-97fd-45d6-acca-8b0abc7fe189)


`GEpiHmfNPehj-aQoWitd/sZWzxps9LkqWENj7tz61/mE_KWXQ-UwK0Xa5HpFKC/5EJgSMP8RHTKwJhmft2d`


We could, fortunately, find one of the instrumental artefacts in the build ID of this sample, which can be incorporated into the detection rule, while hunting for similar samples on various popular malware corpus like VirusTotal and much more. 


Therefore keeping these artefacts in mind, we will move ahead to the ransomware code, using IDA-Freeware.



## Looking into the code using IDA-Freeware.



![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/aaa53632-e4c0-4458-960d-1bd2732d53a4)


We load the sample into IDA-Freeware, and once the initial auto-analysis is completed, we see there's a `main_main` function, which is the function we are interested in for now, let us dive into it, and figure out the rest of the code, and look into every interesting function. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/bc7bdbb5-40aa-43a6-803c-115073129521)


Just after, we land on the first graph inside the main function, we see the first part of the code  `1` which is responsible for setting up the stack frame, local variables and calling GO runtime functions, which are necessary for the program, ending with adding a `nop` instruction either for alignment or padding. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/dbd2ed52-910d-426c-9430-fdf6bb04aed2)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/ad9099fd-087a-4df0-9b03-3f3bfa64ca4f)



In the second part of graph `2`, this code is responsible for first loading a data structure containing a list of processes which are to be terminated. Once it is loaded, there is a call to another function known as `enc_pkill_Pkill`. Let us look into the code, before concluding the working of the function. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/270d1147-04be-4629-a40a-4357f3c60cb9)


Initially, it loops through the processes which, it receives as an argument from the previous data structure containing the list of processes. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/cefd7b40-79ca-41b0-b210-4c48e3f3e802)


Then, it goes ahead and appends the `.exe` extension into the processes which have been loaded from the previous data structure, in case they do not have it. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/71317cda-761c-4ec0-aa44-34050d6c6e63)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/7820861b-a353-48c0-a81e-a3d84f3c2d17)


Then, it goes ahead with appending the `taskkill /im /f ` command to forcibly terminate the process using `taskkill` system utility, which is executed using `os_exec` [golang](https://pkg.go.dev/os/exec) command, which is used to run the system commands in Golang code.  

Therefore, we can now conclude that the second part of the code in this graph is used to terminate the processes using task-kill post-loading the processes. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/8e4379a9-f0d2-417f-9267-10b20f816d61)


Then, moving ahead to the next node, we can see that, in case the code does not find the processes to terminate, it prints a message `Process Not Found` to the standard output. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/4ba5a815-95ff-40d9-ab9d-d1410bb6f390)


Now, moving ahead to the fourth graph node, we can see that in case the processes were terminated, the control flow of the program will pass to this block of code, where we have another function `enc_shadowcopy_Delete`, being called, let us go through this function before moving ahead. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/86ce061d-6adf-4a15-ac95-b0d83531de84)

We can see that this function is responsible for executing `vssadmin delete shadows /all /quiet` which is responsible for deleting all shadow copies. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/a871f01f-fa20-48de-b334-d27af5bd6d92)


Next, we move ahead to the other graph node, where we can see a function, `config_Dirs` being called which is responsible for enumerating all the possible directories present on the drives, this is achieved by constructing a simple loop. 


