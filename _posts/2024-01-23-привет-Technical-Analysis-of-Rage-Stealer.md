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
    - Armory Wallet.
    - Atomic Wallet.
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
    - File Enumeration.
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

Interesting string/s :

- Promotion : `this is a @xStealer ,  devloper - t.me/nsper\n Log`
- Browser names.
- Wallet Names.
- Social Media Software Names.
- `6933559326:AAFCMpCN7nFrropeYTNM00Ix51ZeXISBVaY`: Telegram Bot-Token.
- `6623563227`: Telegram Chat ID.


## Credential & Info Stealing: кошельками.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/0d166441-98d0-4a03-af12-1701e51e351d)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/2a19e5c1-211f-4cc1-8203-a45eeafb530a)

The Rage Stealer supports the stealing capabilities of various wallets & related information. Initially, it enumerates all the available processes and then starts stealing or logging data from various sources and stores it by creating a directory with  the prefix `\\44_23`.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/db8beb4f-ebe0-4ce4-a684-c197077df343)

One of the sources being stolen is the `cryptocurrency` wallets. The functions in the code take the target directory as the parameter and copy the contents inside it.  Let us dive into the code using dnSpy to figure out the supported wallets.

### Armory Wallet.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/2339a446-d244-4091-9b97-1e2c18964df6)

The ArmoryStr function targets Armory wallets (an open-source Bitcoin wallet with Cold Storage and Multi-Signature support). This function uses a try..catch exception handling mechanism and a for each loop to enumerate potential files or profiles related to the Armory wallet. The enumeration takes place in the \\Armory\\ path, and for each file found, the function uses the CopyTo method to duplicate the file into the target directory formed by directorypath + Armory.ArmoryDir. The destination for these files is `\44_23\Wallets\Armory`, indicating to be exfiltrated by the stealer.


### Atomic Wallet.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/d39f69f9-996e-4651-ac3e-a4b60be9cd4c)

The AtomicStr function targets [Atomic Wallet](https://atomicwallet.io/) a cryptocurrency wallet. This function employs a try..catch exception handling mechanism and a for each loop to iterate through files located in the \\atomic\\Local Storage\\leveldb\\ path. For each file discovered, the function creates a corresponding directory in the specified target path (directorypath + AtomicWallet.AtomDir) and duplicates the file into this directory using the CopyTo method. The destination for these copied files is `\44_23\Wallets\Atomic\Local Storage\leveldb\`. The function increments counters (AtomicWallet.count and Counting.Wallets) to keep track of the number of processed files and wallets and makes sure all the profiles are exfiltrated by the stealer. 


### Bitcoin Core Wallet.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/c9ea7cff-daee-4df6-9203-78d8cbe32b6d)

The BCStr function targets  Bitcoin Core wallets. Utilizing a try..catch exception and accesses the Windows Registry to retrieve information about the Bitcoin Core wallet. Specifically, it looks for registry keys under "Software" -> "Bitcoin" -> "Bitcoin-Qt". Upon successfully obtaining this information, the function creates a target directory (directorypath + "\\Wallets\\BitcoinCore\\") and copies the wallet.dat file from the specified location in the registry (registryKey.GetValue("strDataDir").ToString() + "\\wallet.dat") to the newly created directory. The function increments counters (BitcoinCore.count and Counting.Wallets) to track the number of processed files and wallets and makes sure all the wallet profiles are exfiltrated by the stealer. 


### ByteCoin Wallet.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/77778932-216b-40b5-8dfa-5ada81ee4ed9)

The BCNcoinStr function targets ByteCoin cryptocurrency wallet it employs a try..catch exception  and iterates through files in the \\bytecoin directory under the AppData path. For each file found, the function creates a corresponding directory in the specified target path (directorypath + "\\Wallets\\Bytecoin\\"). If the file has a ".wallet" extension, it is copied to the target directory using the CopyTo method. The function increments counters (Bytecoin.count and Counting.Wallets) to keep track of the number of processed files and wallets and makes sure the profiles of the wallet are exfiltrated by the stealer.


### DashCore Wallet.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/61475667-0277-4f6b-9b13-efcc46becf7e)

The DSHcoinStr function targets the DashCore cryptocurrency wallet and it uses a try..catch exception and attempts to access the Windows Registry to retrieve information about the DashCore wallet. Specifically, it looks for registry keys under "Software" -> "Dash" -> "Dash-Qt". Upon successfully obtaining this information, the function creates a target directory (directorypath + "\\Wallets\\DashCore\\") and copies the wallet.dat file from the specified location in the registry (registryKey.GetValue("strDataDir").ToString() + "\\wallet.dat") to the newly created directory. The function increments counters (DashCore.count and Counting.Wallets) to keep track of the number of processed files and wallets and makes sure the profiles of the wallet are exfiltrated by the stealer.


### Electrum Wallet.
