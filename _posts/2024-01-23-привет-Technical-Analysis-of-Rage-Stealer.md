---
title:  "привет: Technical Analysis of Rage Stealer."
layout: post
categories: malware-analysis
---

## Table Of Contents

- Background.
- About Rage Stealer.
- Metadata
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
- Code Attribution.
- Overview.
  
