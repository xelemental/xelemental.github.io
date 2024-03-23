---
title:  "Winver: Reverse-Engineering PatchWork APTs recent Golang implant."
layout: post
categories: reverse engineering
---


## Table Of Contents

- Background
- Overview of the implant.
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

Well, recently in this process of hunting, I did come across a [tweet](https://twitter.com/suyog41/status/1765725837041824121) by fellow security researcher [Yogesh Londhe](https://twitter.com/suyog41), who posted about a fresh implant linked to PatchWork Threat group. Consequently, this blog will predominantly serve as a reverse-engineering side of things rather than a conventional malware analysis discourse.



## Overview of the implant.

