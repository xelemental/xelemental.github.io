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

Now, here we encounter a function named `setConsoleCodePage`, let us go through the workings of this function. 







