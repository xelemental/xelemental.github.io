---
title:  "Planets: Technical Analysis of Planet Stealer."
layout: post
categories: malware-analysis
---


## Table of Contents

- Background.
- About Planet Stealer.
- Metadata.
- Basic Static Analysis.
- Dealing with UPX & Garble.
- Credential & Info-stealing: Part-I
  - Google Chrome.
  - Microsoft Edge.
  - Brave Browser.
  - Amigo Browser.
  - Yandex Browser.
  - Epic Privacy Browser.
  - Vivaldi Browser.
  - Sputnik Browser.
  - 7Star Browser.
  - Cent Browser.
  - Orbitum Browser.
  - Kometa Browser.
  - Iridium Browser.
  - Firefox.
  - uCoz.
  - Torch Browser.
- Credential & Info-stealing: Part-II
  - IP.
  - Country.
  - Username.
  - Hostname.
  - Hardware ID.
  - Windows Version.
  - CPU Enumeration.
  - GPU Enumeration.
- Infrastructure Analysis.
  - Telegram Bot.
  - About C2.
  - IOCs.
- YARA Rules.




## Background

Recently, there has been quite an upsurge in the development and advent of new stealers in the underground market. Due to the highly oversaturated market, the demand for generic info stealers has not increased. Due to the excessive competition amongst the various generic products, limiting the anomalies shown by various generic stealers has been challenging for the developers to sustain and make profits. 

A prime example of this would be the recent competition at a well-known forum known as XSS, where competition had been conducted and the most innovative product has been awarded, through this competition, our threat research team did encounter various stealers like WireTap and many others. 

Therefore, looking in search of emerging info stealer campaigns, our threat research team did come across a new stealer, which as well as been discovered by other prominent researchers of the infosec community known as Planet Stealer. 


