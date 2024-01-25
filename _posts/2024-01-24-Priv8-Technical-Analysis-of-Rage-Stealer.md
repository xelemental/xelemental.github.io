---
title:  "Priv8: Technical Analysis of Rage Stealer."
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
    - Steam.
- Credential & Info Stealing: Part IV
    - Discord.
    - FileZilla.
    - Telegram.
    - VimeWorld.
- Credential & Info Stealing: Part V
     - Chrome.
- Infrastructure Analysis.
     - Exfiltration using Telegram.
     - Exploring Telegram C2 & Stealer Channel.
     - Recovering Stolen credentials using TeleCommd. 
- Victim Landscape. 
- Code Attribution.
- Developer Portfolio.
- YARA Rule.



## Background.

Five days ago, I stumbled upon a [tweet/post](https://twitter.com/suyog41/status/1748171535620411653?s=46) by fellow security researcher [Yogesh Londhe](https://twitter.com/suyog41/), who goes by the handle @suyog41. The post highlighted an updated sample of Rage Stealer, a re-branded version of Priv8 (pronounced as частный aka Private) stealer, currently circulating in the wild. Despite the stealer's presence in the wild in 2023, I chose to focus on this recent sample. In this blog, we will delve into the technical capabilities of Rage Stealer and conduct an infrastructure analysis. Additionally, we will employ a tool we've been developing called [`TeleCommd`](https://github.com/RixedLabs/TeleCommd) to extract and analyze the harvested stolen credentials.


## About Rage Stealer.

![Blank diagram(4)](https://github.com/xelemental/xelemental.github.io/assets/49472311/4a24ebfc-ae34-4b0e-a8ce-e7eb57fb6492)



Rage Stealer initially surfaced on the wild back in August 2023, as reported by Yogesh. Initially, it was named Priv8 stealer, but after rebranding it had a new name and some code omissions were made and it was renamed RageStealer or xStealer. The base stack of this stealer is .NET and  a Telegram Bot which it uses to forward the stolen logs, the developer of this stealer is a Vietnamese guy, who mimics a Russian individual, by adding Russian texts inside the sample.


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



## Credential & Info Stealing: Part III

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/c253c517-ffe5-4229-a939-01692ea0f328)

After stealing the system information, the stealer then moves ahead to stealing VPN applications & Gaming Profiles. Let us dive into the code and check it out. 



### ProtonVPN

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/75b6a0b9-892f-48a9-84c4-398dfe222a05)

The function `Save` from the class `ProtonVPN` enumerates directories in the system, it then checks for the existence of this directory and, if present, proceeds to iterate through its subdirectories. Within each subdirectory, the method checks for the presence of `ProtonVPN.exe` in the path. For directories containing the executable, it further enumerates subdirectories and, for each, identifies the `user.config` file. The method then creates a corresponding directory structure in the exploitation directory AKA the directory to be exfiltrated, named after the parent directory of the `user.config` file. If the destination directory doesn't exist, it is created, and the `user.config` file is copied to this location. The process increments the Counting.ProtonVPN counter for each successfully saved ProtonVPN configuration, The method aids the stealer in the extraction and organization of ProtonVPN configurations for exfiltration.


### OpenVPN

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/2773b874-e5f0-48bb-90bf-357df63967ea)

The function `Save` from the OpenVPN class enumerates directories in the system. It does it by first defining the target exploitation directory (exploitDir AKA the directory to be exfiltrated) using the Help class. Then, it constructs the path to the OpenVPN Connect profiles directory within the user's application data folder. If this directory doesn't exist, the method terminates. Upon confirming the existence of the profiles directory, the method creates a corresponding directory structure in the exploitation directory (exploitDir + "\\VPN\\OpenVPN"). It proceeds to iterate through the files in the OpenVPN profiles directory, identifying those with the `ovpn` extension. For each matching file, it copies it to the designated exploitation directory with the same filename. The method increments the Counting.OpenVPN counter to track the number of OpenVPN configurations successfully captured, the method aids the stealer in the extraction and organization of OpenVPN profiles in a certain specific directory for exfiltration. 

### NordVPN

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/b360a263-6a7e-44a3-885c-2d94ed8921bc)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/fbe93221-c1b3-4cc9-b002-5af4340a4cf4)

The `Save` function within the NordVPN class enumerates directories by utilizing the `GetDirectories` method and searches for NordVPN. Once the relevant directory is identified, it further explores subdirectories to locate the executable named NordVPN.exe. The function checks for the existence of the `user.config` files within these subdirectories. Upon discovering such a file, it creates a corresponding directory structure within the exploitDir (the directory designated for exfiltration). After loading the content of the XML file, it proceeds to decode the encoded credentials using the Decode method. The decoded credentials are then appended to a new file named `accounts.txt` in the exploitDir directory. This process systematically extracts and decodes NordVPN credentials, organizing them in a proper manner for exfiltration.



### Steam.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/be0c2cc4-9d47-41be-9b6b-0bff92d36674)

The `SteamGet` function within the Steam class, enumerates the Steam directory, then goes ahead and copies all the credentials in a file known as `AccountsList.txt` , the exfiltrated information contains information like names of Games & user config. 



## Credential & Info Stealing: Part IV

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/283fb96c-4e22-4654-949d-b22cae81ad45)

Once, it is done stealing the VPN and gaming profiles and the passwords, it then moves ahead to steal the sensitive information related to social media services like Telegram, VimeWorld, and Discord. Let us go ahead and check it out. 



### Discord.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/3413e92f-8203-4c48-bbd2-b685bb588ce5)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/15f80a50-2915-4f71-8f02-b944c9f6e651)

The `GetTokens` method of the Discord class, enumerates the following directories, and once it is found, it then looks for files with extensions `.log` & `.ldb` . Once the `GetFiles` returns that the file has been found, it uses the constant `TokenRegex` to match and look for Discord Tokens, and this process keeps up happening recursively as the method employs `foreach` until there is no file left in the directory to be checked against the following conditions. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/8e3d10f2-fdcb-41c0-b6f1-5f2c7ea20353)

Once, the tokens are harvested from the files, then the `WriteDiscord` method in the Discord class uses `AppendAllText` to save the contents inside a file called `Tokens.txt` which will be later used for exfiltration. 


### FileZilla.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/43b6f07c-b220-4069-b8ea-a71f49aa3cdb)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/4a9195ee-94b8-41a7-9eb1-5a63b4239ea4)

The `GetDataFileZilla` method from the FileZilla Class reads the specified FileZilla configuration file (recentservers.xml), extracts server details (host, port, user, and password), and appends the information to a StringBuilder (FileZilla.SB), then it appends the details to a log file (FileZilla.log) in the exploit directory which is to be exfiltrated. 



### Telegram.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/5f2a852c-d2a0-4f8e-b5a4-b45f77e4ff23)

The GetTelegramSessions method in the `Telegram` class retrieves Telegram session data. It searches for Telegram data directories, copies specific files and directories to a new location, and counts the number of Telegram sessions found. The copied files include those related to user tags, settings, and key data, and the function excludes files larger than 5 KB. The copied data is stored in a directory within the specified exploitdirectory which is to be exfiltrated. 



### VimeWorld. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/7b6e4702-c1ef-4f68-b34b-7edb329c6a49)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/609c9675-c2b6-47b5-8c78-4b29f4fb7e5e)


The Get function is in the "Vime" class which is responsible for retrieving VimeWorld player information. It reads data from a configuration file, checks for the presence of a "password" keyword, and if found, proceeds to create a directory for VimeWorld data within the specified exploit directory. It then downloads player information from a VimeWorld API, encrypts and saves relevant data, including player nickname, rank, level, and unique identifier (OSSUID). The saved data is organized into a file named after the player's nickname. The associated functions Level(), Donate(), OSSUID(), and NickName() handle specific aspects of extracting player information and then the data is saved for exfiltration. 


## Credential & Info Stealing: Part V

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/63f9c912-ea7a-437c-93c2-c8371cdd02f5)

Once the stealer is done stealing the social media information, it then moves ahead to stealing Chrome-based sensitive data that is cookies and passwords. Let us explore the code. 


### Chrome.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/cceca29d-da9e-4bd4-ba80-f55d803fcad8)

Out of the two functions, looking into the first method the `GetPasswords` method is responsible for asynchronously retrieving stored passwords from the Google Chrome browser. It first checks for the existence of the Chrome browser directory, and if it is found, it then attempts to obtain the encryption key asynchronously. Subsequently, the code iterates through files named `Login Data` within the Chrome directory and its subdirectories. For each file, it copies the data to a temporary location, processes the SQLite database containing login information, and decrypts passwords using the obtained encryption key. The decrypted information, including URLs, usernames, and passwords, is stored in instances of a PasswordFormat class. The method handles exceptions and, upon completion, returns an array containing the collected password information. The implementation involves asynchronous tasks, encryption key retrieval, SQLite database handling, and password decryption to achieve the extraction of Chrome-saved passwords.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/22d56f02-c7dc-41f9-93db-3c68c6387bd0)

Now, the second one the `GetCookies` method is responsible for retrieving stored cookies from the Google Chrome browser. Initially, it checks for the existence of the Chrome browser directory. If the directory is found, it asynchronously attempts to obtain the encryption key used for decrypting sensitive data. The code then iterates through files named `Cookies` within the Chrome directory and its subdirectories. For each file, it copies the data to a temporary location, processes the SQLite database containing cookie information, and decrypts cookie values using the obtained encryption key. The decrypted details, including host, name, path, value, and expiry timestamp, are stored in instances of a `CookieFormat` class. Similar to the password extraction process, the method handles exceptions and, upon completion, returns an array containing the collected cookie information. The implementation involves asynchronous tasks, encryption key retrieval, SQLite database handling, and cookie value decryption to achieve the extraction of Chrome-saved cookies. The Chrome browser path and encryption key are declared as constants within the class.


## Infrastructure Analysis.

Now, after looking into the stealer capabilities and features, in this section, we will focus on the analysis of the code responsible for exfiltration. Then we will do a little bit of analysis on the Telegram Channel. Let us dive inside the code without any delay. 


### Exfiltration using Telegram

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/b9e4094b-3b73-4d72-97bf-50d73bd54006)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/aa795a2b-1093-42bc-9403-f6173e36d21e)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/b58fdd7e-da7e-434e-bffe-992113c5614a)


The exfiltrated data is concatenated which contains the IP and other stolen artefacts as a `caption` which is then uploaded as a Zipped version and then using a certain telegram bot API token is exfiltrated to a certain channel where the malicious threat actor is waiting for the logs. 


### Exploring Telegram C2.

I have been using a tool developed by me & Kumar[https://github.com/DoubleAtoString] known as TeleCommd[https://github.com/RixedLabs/TeleCommd] to enumerate information about telegram bots and channels, it supports various capabilities like forwarding stolen logs in NodeJS & Python, and we do plan to open-source it in few days. 

Let us find the name of the bot using TeleCommd. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/05c56c30-ee63-4bab-8b23-78b877497012)

We can see that the name of the bot is `logs_nsper_bot`. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/612f10c6-d377-4f32-b112-476de343bf8e) 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/29591f6a-999e-47d0-8028-1a64be63c84f)


Now, upon looking into the description of the bot, we can see the link to the official channel & author of the market. Let us look into the official channel. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/925b869b-e341-42b4-964c-0e3beeb4cc2f)

And, we can see that this .NET stealer is for sale per build worth 15 US Dollars. 



## Recovering Stolen credentials using TeleCommd.

Now, that we have the API Token, and the channel ID let us recover the stolen credentials using Telecommd. Initially, we will see the number of victims.

![xStealer(1)](https://github.com/xelemental/xelemental.github.io/assets/49472311/5eeb2a42-91f0-4b94-8e6d-7bf02e23111d)

As, we can see there are only 72 victims to date, as the script stops dumping logs for the 73rd user. But there might be cases where similar logs have been dumped multiple times. Therefore, we will sort that out in the victim landscape section.

![nsper12](https://github.com/xelemental/xelemental.github.io/assets/49472311/e3ea371b-f503-405c-b526-715b6fb56e90)


Finally, we were able to retain the stolen credential using TeleCommd. Now let us do some vetting focused on the collected dump. 


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/376a0fcc-29c3-49db-b3a7-826e76d2f7d9)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/86eb7be3-65b6-4ea2-b27e-b71a047504e1)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/6d321333-63e8-40c2-8c4f-906c06d6ebf3)


This clarifies that the dumped logs by our script are legitimate, with the most recent victim being from Germany. Due to its low price, it's easily being purchased by individuals and is currently active ITW(In the Wild). 


## Victim Landscape.

![ChartGo](https://github.com/xelemental/xelemental.github.io/assets/49472311/bf763e1e-b07c-49e8-b1c9-6aaa601647c5)

After carefully sorting the data, it became crystal clear that there have been only 41 victims across the globe infected by Rage Stealer with the United States having 13 individuals affected to Switzerland having only a single victim. 


## Code Attribution.

The code from this stealer, resembles the same codebase as [BlackGuard .NET Stealer](https://cyble.com/blog/dissecting-blackguard-info-stealer/), just the only difference is the use of .NET protector and some variable renaming. Another similarity from version one of Priv8 or Rage Stealer resembles a python stealer which is also known as RageStealer, uploaded by the developer of this stealer, you can find the repository [here](https://github.com/RAGE217/RageStealerV3). 


## Developer Portfolio.

The Rage Stealer is developed by a Vietnamese guy AKA `Trương Ngọc Khánh` . Trương frequently maintains decent activity at his [Original GitHub account](https://github.com/TNK-ADMIN) where he mentions his general whereabouts that is his social accounts & his [website](https://tnkdev.io.vn/) which now just returns a JSON of his Facebook profile. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/2548a487-5b22-4781-bf39-a76a6bb06954)

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/f07faa1f-dcc9-42c4-9d01-a8228aecb8b7)


He loves programming in Python, so he initially programmed Rage Stealer in Python, created an alias and uploaded his work to an alternate Github account. 

![F1zWMjvWYAAQnu5](https://github.com/xelemental/xelemental.github.io/assets/49472311/f83b4669-08fc-4f78-ab6a-3d12020f36a7)

Later, the same stealer was re-written by him and was detected by Yogesh's hunting rules. 

![F1zWRu7XsAA4OOm](https://github.com/xelemental/xelemental.github.io/assets/49472311/19bbba83-4423-433c-bdbb-15e7616d595e)

This log, from Yogesh's tweet, clearly shows that the channel name goes by `Tnk_K07VN`.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/b05f5965-0af7-4b88-b327-6abc17005add)


![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/c7550e00-058e-46ae-937f-c557e4c2f3c9)



Now, as we know pretty well Trương is an avid Python programmer, he then decided to release [two projects](https://pypi.org/user/k07vn/) one of obfuscation and the other generally a cryptography-based project. One of them had his name, his alias mentioned. 

Now, after a little bit of re-branding and removing the Roblox part of the stealer and the credit card stealing part, Trương has dumped his old alias and is now known as `nsper` and Rage Stealer has been re-branded to xStealer. 


## YARA Rule

Wrote a very simple YARA Rule, if you feel something is wrong with it, please reach out! Thanks! 

```yara
import "pe"

import "pe"

rule RageStealer 
{
    meta:
        author = "ElementalX"
        date = "2024-01-24"
        description = "Detects Rage-Stealer"
        hash = "0623dbe28b6054553016d7d43bf876a1"
        source = "https://xelemental.github.io/Priv8-Technical-Analysis-of-Rage-Stealer/"
    strings:
        $str0 = "RageStealer"
        $str1 = "Chrome"
        $str2 = "xStealer"
        $str3 = "ProtonVPN"
        $str4 = "zip"
        $str5 = "Grabbed Files"
        $str6 = "Armory"
        $str7 = "Exodus"
        $str8 = "Information.txt"
        $str9 = "Discord"
    condition:
        uint16(0) == 0x5a4d and
        filesize < 1MB and
        7 of them
}









