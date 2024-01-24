---
title:  "привет: Technical Analysis of Rage Stealer."
layout: post
categories: malware-analysis
---

## Table Of Contents

- Background.
- About Rage Stealer.
- Metadata.
- Basic Static Analysis.
- Credential & Info Stealing: кошельками.
    - File Enumeration.
    - Armory Wallet.
    - Bitcoin Core Wallet.
    - ByteCoin Wallet.
    - DashCore Wallet.
    - Electrum Wallet.
    - Ethereum Wallet.
    - Litecoin Core Wallet.
    - Monero Wallet.
    - Exodus Wallet.
    - ZCash Wallet.
    - Jaxx Liberty Wallet.
    - Overview.
- Credential & Info Stealing: СистемИнфа.
    - GeoIP.
    - Screen Grabbing.
    - Process Enumeration.
    - System Enumeration.
- Credential & Info Stealing : виртуальная частная сеть
    - ProtonVPN.
    - OpenVPN.
    - NordVPN.
- Credential & Info Stealing : Социальные сети и обмен информацией
    - Discord.
    - FileZilla.
    - Telegram.
    - Vime.
- Credential & Info Stealing : браузер
     - Chrome
     - Firefox
- Infrastructure Analysis.
     - Exfiltration using Telegram.
     - Exploring Telegram C2.
- Victim Landscape. 
- Code Attribution.
- YARA Rule.
- Developer Portfolio. 
- Overview.


## Background.

Five days ago, I stumbled upon a [tweet/post](https://twitter.com/suyog41/status/1748171535620411653?s=46) by fellow security researcher [Yogesh Londhe](https://twitter.com/suyog41/), who goes by the handle @suyog41. The post highlighted an updated sample of Rage Stealer, a re-branded version of Priv8 (pronounced as привет) stealer, currently circulating in the wild. Despite the stealer's presence in the wild, I chose to focus on this recent sample. In this blog, we will delve into the technical capabilities of Rage Stealer and conduct an infrastructure analysis. Additionally, we will employ a tool we've been developing called [`TeleCommd`](https://github.com/RixedLabs/TeleCommd) to extract and analyze the harvested stolen credentials.


## About Rage Stealer.

Rage Stealer initially surfaced on the wild back in August 2023, as reported by Yogesh. Initially, it was named Priv8 stealer, but after rebranding it had a new name and some code omissions were made and it was renamed RageStealer or xStealer. The base stack of this stealer is programmed in .NET and it uses a Telegram Bot to forward the stolen logs the developer of this stealer is a Vietnamese guy, who mimics a Russian individual, by adding Russian texts inside the sample.


## Metadata.

SHA-256: bcbbd089fd08706e25137d0ec7727bd07ebba568876f69acc367e2a96fffdfbc.
Sample: Available [here.](https://www.virustotal.com/gui/file/bcbbd089fd08706e25137d0ec7727bd07ebba568876f69acc367e2a96fffdfbc/) 


## Basic Static Analysis.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/31b36cd8-e927-4a11-9404-c566a8c62881)

The filename of this sample is `MineCraft.exe`, and upon checking the code, it is crystal clear that the stealer is not using any sort of obfuscator or packer like other .NET Stealers. Upon checking this sample on VT, the threat is labelled as a data stealer. 

