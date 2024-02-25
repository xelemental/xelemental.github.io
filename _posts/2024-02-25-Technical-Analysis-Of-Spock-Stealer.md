---
title:  "SpockStealer: Technical analysis of a Golang-based credential stealer."
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
    - Overview.
- Infrastructure Analysis.
- YARA Rule.
- MITRE ATT&CK.
- Summary.
- Resources.



## Background.

Recently, while I was browsing X previously known as Twitter, I stumbled upon a tweet or post by a fellow security researcher
[Yogesh Londhe](https://twitter.com/suyog41) mentioned an uncommon stealer name, which I had never heard of, also known as Spock Stealer.

With the rise of modern compiled languages and the constant influx of the notion that malicious software written in languages like Go or Rust is cumbersome to analyze and dissect, coupled with the oversaturation of the stealer market, it seems like every aspiring programmer's go-to learning project is developing a stealer. Well, it does be like that sometimes. If you doubt this claim, I invite you to search the keyword 'Stealer' on GitHub, Telegram, and popular forums.

Initially, I thought Spock Stealer might bring something innovative in terms of functionality and overall quality. Unfortunately, I was disappointed to discover that it is just another basic stealer developed in Go. As an analyst, I'm unaware of the infection vector of this stealer, but I must commend the author for not using a precompiled GitHub project as part of the campaign, unlike this [threat actor](https://xelemental.github.io/Golang-based-credential-stealer-targets-Indian-Airforce-Officials/).

Therefore, in this blog, I will walk through the technical aspects of this stealer and provide some YARA rules for fellow researchers.


## Stealer Analysis

In this section, we will perform some technical analysis on the stealer. 


### Metadata

SHA-256 : 89300678df750de360222d0cefbebb4291f30c5aec86c2cdaab32b0f09891e94.
Sample: Available [here.](https://bazaar.abuse.ch/sample/89300678df750de360222d0cefbebb4291f30c5aec86c2cdaab32b0f09891e94).


### File Information.

File Name: ` docx.exe `.

File Creation Time: `Unknown`.

Go-build ID: `"hyJI5wXtKgEwMeLZtwm5/SkRZinb1FBXW1ONyASbu/SlLnz5DZLKjb_mHyQtXl/tYupb-n1J34C4eBJLKsB"`

File Type: `Portable Executable 64`

VirusTotal Detection: `9/72` 


### Analysis of the stealer using IDA-Freeware.


