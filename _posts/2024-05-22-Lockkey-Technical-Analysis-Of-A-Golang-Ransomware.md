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

