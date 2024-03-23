---
title:  "Winver: Reverse-Engineering PatchWork APTs recent Golang implant."
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

Thanks to PEStudio, for these details. Pretty impressive tool as always, it mapped few artefacts making it more clear, giving a clear overview of the sample. 


