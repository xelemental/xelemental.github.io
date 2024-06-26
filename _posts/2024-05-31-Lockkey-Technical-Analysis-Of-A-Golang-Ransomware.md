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
- Workflow.
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


Then, it goes ahead and appends the `.exe` extension into the processes loaded from the previous data structure, in case they do not have it. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/71317cda-761c-4ec0-aa44-34050d6c6e63)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/7820861b-a353-48c0-a81e-a3d84f3c2d17)


Then, it goes ahead with appending the `taskkill /im /f ` command to forcibly terminate the process using `taskkill` system utility, which is executed using `os_exec` [golang](https://pkg.go.dev/os/exec) command, which is used to run the system commands in Golang code.  

Therefore, we can now conclude that the second part of the code in this graph is used to terminate the processes using task-kill post-loading. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/8e4379a9-f0d2-417f-9267-10b20f816d61)


Then, moving ahead to the next node, we can see that, if the code does not find the processes to terminate, it prints a message `Process Not Found` to the standard output. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/4ba5a815-95ff-40d9-ab9d-d1410bb6f390)


Now, moving ahead to the fourth graph node, we can see that in case the processes were terminated, the control flow of the program will pass to this block of code, where we have another function `enc_shadowcopy_Delete`, being called, let us go through this function before moving ahead. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/86ce061d-6adf-4a15-ac95-b0d83531de84)

We can see that this function is responsible for executing `vssadmin delete shadows /all /quiet` which is responsible for deleting all shadow copies. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/a871f01f-fa20-48de-b334-d27af5bd6d92)


Next, we move ahead to the other graph node, where we can see a function, `config_Dirs` being called which is responsible for enumerating all the possible directories present on the drives, achieved by looping over the existing drives.


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/c4e8f2c6-ca6e-4984-b88b-66fed47f9f23)

Now, we can see that in the fifth[`5`] node of the graph, we have a simple comparison against the `rax` register, and the code flow jumps to the sixth[`6`] node of the graph, let us explore the first function inside the sixth graph node, which is `main_main_func1`.



![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/4a11e8c1-98b6-4b99-aa4a-dafe24ce3cc7)


Initially, as we saw that the code, where it enumerated the directories, this function uses those enumerated directories, at first it prints a `Walking` message.


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/0c1bf630-8a7d-4daf-9c24-a25de367c09e)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/6a67cf1e-c76c-45ea-94b6-a1503aa2b348)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/2f9828df-85a3-4b46-b262-832031b4545d)




Then, using `path_filepath_Base` it gets the base name of the file from the directory, later when the check is fulfilled, it goes ahead and prints another message known as `Good File`, which is further processed in a Queue for locking. Now, once this task is complete, it calls another function known as `main_main_func1_1`. Let us check out the working of the function. 



![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/fe7a06ec-fbc8-4280-a98e-d2a72b7eb353)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/9d82e914-6a3d-4793-8378-4eaa8cb4d3b8)


After, we navigate to the function, `main_main_func1_1`, we can see that there is a call to another function, known as `enc_encryption_EncryptFiles` , which is responsible for encrypting all the files pushed into the Queue, in the previous function. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/18b0921b-9c8c-4e52-b6cd-ea072dc8d5d0)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/e4a4c3fa-1554-47d2-959d-3f60727afc07)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/cbcd8dc4-735b-4cf4-b2d8-9678165c02d4)


From, the above function, it is now clearly evident that, the code is using AES to encrypt the files, and replacing their extension with `.lock` . Now, once we have looked into this function, let us go to the caller of this function, which is `main_main_func1` function. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/eb7c60ae-4589-45f3-9966-5940c745998d)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/e394d373-3c9f-476b-951a-14fdd56fe4ec)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/e2737c9b-5cda-4b5a-9ca9-a53a4933b332)


Now, after scrolling a little bit after the function(`main_main_func1_1`) has returned we can see that the config note stored in the `.rdata` section is being loaded, and finally the contents are written into a file known as `ВОССТАНОВИТЬ ФАЙЛЫ.txt` using the `os_WriteFile` function, and with this we, have the work of this function complete, and now it is returned to the caller `main_main` . 


Now, we have explored the functions, resposnible for walking the directories, and encrypting the contents using AES algorithm, we are done with the [`6`] graph node, and this path continues for all the files which are present on the target machine, over all existing drives. Next, we will move to the last interesting graph which is [`7`]. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/26914552-cabd-4d32-95a8-e4e352537088)

![GOGiyM-WsAA7y6L](https://github.com/xelemental/xelemental.github.io/assets/49472311/541cfe25-8c01-46ff-98f9-a603dbf3b5fb)


Here, we can clearly see that `MessageBox` API is used print this message `ВНИМАНИЕ! , Система вашей компании была полностью скомпрометирована.Все ваши критичес кие данные были зашифрованы. `, with a title of the messagebox being `Locker` , and finally pops the messagbox, which notifies the user's data have been locked. 

With, this we are done exploring the code using IDA-Freeware.



## Workflow.



![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/febc2e6e-6843-4995-a0a6-b189a9974f49)



## YARA Rule.

I did draft a very basic YARA Rule for detecting the ransomware variant, if you find the rule needs fine-tuning or it needs some sort of fixation, please do let me know, thank you in advance!

```
rule Lockkey {

    meta:
        description = "Detecting Lock-key Ransomware"
        author = "ElementalX"
        date = "2024-05-31"
        rule_version = "1.0"
        malware_type = "Ransomware"

    strings:

        $process_kill = { BA 10 00 00 00 87 51 20 48 8B 0D ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 89 C8 48 89 D1 E8 ?? ?? ?? ?? }
        $shadow_copydelete = { 48 8D 15 ?? ?? ?? ?? 48 89 94 24 ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 89 94 24 ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 89 94 24 ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 89 94 24 ?? ?? ?? ?? 48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? BB ?? ?? ?? ?? 48 8D 8C 24 ?? ?? ?? ?? BF ?? ?? ?? ?? 48 89 FE E8 ?? ?? ?? ?? }
        $walking_file_encryption = { 44 0F 11 BC 24 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 89 94 24 ?? ?? ?? ?? 48 8D 74 24 30 48 89 B4 24 ?? ?? ?? ?? 48 8B 74 24 48 48 89 B4 24 ?? ?? ?? ?? 48 8B 7C 24 68 48 89 BC 24 ?? ?? ?? ?? 48 8D 8C 24 ?? ?? ?? }
        $ransom_note = "Система вашей компании была полностью скомпрометирована"
        $go_build = "GEpiHmfNPehj-aQoWitd/sZWzxps9LkqWENj7tz61/mE_KWXQ-UwK0Xa5HpFKC/5EJgSMP8RHTKwJhmft2d"
   
   condition:
           uint16(0) == 0x5A4D and
           uint32(uint32(0x3C)) == 0x00004550 and 
           all of them
    }
       
```


## MITRE ATT&CK.


T1057 - Process Discovery.

T1489 - Service Stop.

T1490 - Inhibit System Recovery.

T1082 - System Information Discovery.

T1486 - Data Encrypted for Impact.



## Author's two cents.

It was fun analyzing a golang based simple ransomware, hope you enjoyed reading my approach towards analyzing this ransomware, if you find anything suspicious or wrong, please do reach out to me. 



## Resources.

- Go Docuemntation.
- MSDN.
- MITRE ATT&CK Framework.
