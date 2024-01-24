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
- Credential & Info Stealing: Part-I.
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
- Credential & Info Stealing: Part II.
    - GeoIP.
    - Screen Grabbing.
    - Process Enumeration.
    - System Enumeration.
- Credential & Info Stealing: Part III
    - ProtonVPN.
    - OpenVPN.
    - NordVPN.
- Credential & Info Stealing: Part IV
    - Discord.
    - FileZilla.
    - Telegram.
    - Vime.
- Credential & Info Stealing: Part V
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


## Credential & Info Stealing: Part-I.

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

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/d8be3aba-058e-4064-9426-7ee6f1db248d)

The EleStr function targets Electrum Wallet and it utilizes a try..catch exception and iterates through files in the \\Electrum\\wallets directory under the AppData path. For each file found, the function creates a corresponding directory in the specified target path (directorypath + Electrum.ElectrumDir). The file is then copied to this target directory using the CopyTo method. The function increments counters (Electrum.count and Counting.Wallets) to keep track of the number of processed files and wallets and makes sure the profiles of the wallet are exfiltrated by the stealer.


### Ethereum Wallet.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/1ae56507-50f1-40e1-bf33-7859498f7072)

The EcoinStr function targets Ethereum Wallet and it uses a try..catch exception and iterates through files in the \\Ethereum\\keystore directory under the AppData path. For each file found, the function creates a corresponding directory in the specified target path (directorypath + Ethereum.EthereumDir). The file is then copied to this target directory using the CopyTo method. The function increments counters (Ethereum.count and Counting.Wallets) to keep track of the number of processed files and wallets and makes sure the profiles of the wallet are exfiltrated by the stealer.



### Litecoin Core Wallet.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/40e0153b-8144-4a6a-b95d-e165fe11629f)

The LitecStr function targets Litecoin Wallet and it uses a try..catch exception and then it attempts to access the Windows Registry to retrieve information about the Litecoin Core wallet. Specifically, it looks for registry keys under `"Software" -> "Litecoin" -> "Litecoin-Qt"`. Upon successfully obtaining this information, the function creates a target directory (directorypath + "\\Wallets\\LitecoinCore\\") and copies the wallet.dat file from the specified location in the registry (registryKey.GetValue("strDataDir").ToString() + "\\wallet.dat") to the newly created directory. The function increments counters (LitecoinCore.count and Counting.Wallets) to keep track of the number of processed files and wallets and makes sure the profiles of the wallet are exfiltrated by the stealer.


### Monero Wallet.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/55e6ed30-caae-4fc3-b921-9e881dda94f2)

The XMRcoinStr function targets Monero Wallet and it uses a try..catch exception and attempts to access the Windows Registry to retrieve information about the Monero wallet. Specifically, it looks for registry keys under `"Software" -> "monero-project" -> "monero-core"`. Upon successfully obtaining this information, the function creates a target directory (directorypath + Monero.base64xmr) and copies the wallet file from the specified location in the registry. The function increments counters (Monero.count and Counting.Wallets) to keep track of the number of processed files and wallets and makes sure the profiles of the wallet are exfiltrated by the stealer.


### Exodus Wallet.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/f5cc62ed-2b34-4f03-ba3c-0e8606530097)

The ExodusStr function targets the Exodus Wallet and it uses a try..catch exception and iterates through files in the `\\Exodus\\exodus.wallet\\` directory under the AppData path. For each file found, the function creates a corresponding directory in the specified target path (directorypath + Exodus.ExodusDir). The file is then copied to this target directory using the CopyTo method. The function increments counters (Exodus.count and Counting.Wallets) to keep track of the number of processed files and wallets and makes sure the profiles of the wallet are exfiltrated by the stealer.


### ZCash Wallet.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/d2e82695-cba2-4dd8-a5d7-a10a127692f0)

The ZecwalletStr function targets the ZCash Wallet and it uses a try..catch exception and iterates through files in the `\\Zcash\\` directory under the AppData path. For each file found, the function creates a corresponding directory in the specified target path (directorypath + Zcash.ZcashDir). The file is then copied to this target directory using the CopyTo method. The function increments the counter (Counting.Wallets) to keep track of the number of processed wallets and makes sure the profiles of the wallet are exfiltrated by the stealer.


### Jaxx Liberty Wallet.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/2dca870b-2e60-4c52-bfc4-e8e4c426fc92)

The JaxxStr function targets the Jaxx Liberty wallet and it uses a try..catch exception & iterates through files in the `\\com.liberty.jaxx\\IndexedDB\\file__0.indexeddb.leveldb\\` directory under the AppData path. For each file found, the function creates a corresponding directory in the specified target path (directorypath + Jaxx.JaxxDir). The file is then copied to this target directory using the CopyTo method. The function increments counters (Jaxx.count and Counting.Wallets) to keep track of the number of processed files and wallets and makes sure the profiles of the wallet are exfiltrated by the stealer.


### Overview.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/07eb4a1b-180b-4066-ace7-98e0673c1372)

Once the stealing is performed the credentials of the wallets are loaded into their specific directories and in case this fails, the message `Старт грабера с кошелями дал сбой"` is printed by this sample indicating a failed task of wallet information stealing. 


## Credential & Info Stealing: Part II.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/83e05c2c-5ccd-4a4b-81d9-fa9daaca0253)

The Rage Stealer, post stealing wallet profiles and information, also exfiltrates various system information like a list of processes, geolocation, and various other system-based information. Let us dive into that.


### GeoIP.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/65e48c5a-b658-4379-97ee-5fa43d95f81f)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/994a0a94-38d2-432c-b472-48e4d610a64a)

The `Ethernet` function uses a try..catch exception to and inside the `try` block of code it uses `https://ip-api.com/` geolocation API to query the current geolocation of the system and retrieves it in an XML format. 


### Screen Grabbing.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/761177b4-9f89-4d54-9dcc-f57bc59b4477)

The `GetScreen` function utilizes the `BitMap` object to create dimensions of the size of the screen and then uses the `Graphics.CopyFromScreen` method to copy and then saves the image in a PNG format using the `Save` method from the bitmap object with a filename `Screen.png` for exfiltration. 


### Process Enumeration.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/68e29674-e91f-4ab6-8732-53dd96980de7)

The `WriteProcess` function uses a for-each loop inside which it employs the `GetProcess` method to enumerate all processes and saves the name of the processes inside a file which is created for exfiltration known as `\\Process.txt` . The other function `ProcessExecutablePath` enumerates the executable path of the process's binaries with a format `Process ID: Executable Path `. 


### System Enumeration.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/c14f7310-71ff-4887-8ab6-f7da3d4e5a7b)

The `GetSystem` function uses various other methods from the SystemInfo Object like `GetSystemVersion` which returns the OS version, then it queries the clipboard data using another method `GetBuffer`, then it uses method `ScreenMetrics` to query the screen resolution, and then uses `GetProcessorID` to enumerate the HWID and then it queries the CPU information using the `GetCPUName` which returns the processor information, and then it uses `GetRAM` method to query the physical memory available in the target computer, then it queries GPU information using the `GetGpuName` method and finally it uses `IP * Country` which returns the IP address and the two-letter country code and finally the BSSID using the `GetBSSID` method. After querying all this information, it saves it in a file known as `\\Information.txt` for exfiltration. 



