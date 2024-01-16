---
title:  "GoStealer: Golang-based credential stealer targets Indian Airforce Officials."
layout: post
categories: malware-analysis
---

## Table Of Contents

- Background
- Malicious ISO Analysis
    - Metadata
    - What is this ISO about?
    - Extracting malicious artefacts.
    - Analyzing malicious artefacts.
    - What is the decoy document about?
    - Overview.
- Stealer Analysis
    - Metadata
    - File Information.
    - Functionality of the malware.
    - Features of the malware.
    - Open Source packages used.
    - YARA Rule.
    - Overview of the Stealer.
 - Infrastructure Analysis 
    - Finding Slack Channel using SlackPirate.
    - Overview of the Slack C2.
 - MITRE ATT&CK Mapping.
 - Summary
 - Resources

## Background

![Infection-Chain](https://github.com/xelemental/xelemental.github.io/assets/49472311/b34b3986-3854-4ab4-a553-1d3be9eedfa2)



This blog delves into the analysis of a stealer written in the  modern-day compiled language, Golang. Luckily, I came across a [tweet](https://twitter.com/Cuser07/status/1745356248307159163) by a fellow security researcher who goes by the alias [@Cuser07](https://twitter.com/Cuser07/), mentioning an intriguing ISO that has been uploaded from India. In addition to examining the stealer, this blog will concentrate on extracting malicious content from the ISO and implementing YARA Rules for hunting.


## Malicious ISO Analysis

### Metadata

SHA-256 : 4fa0e396cda9578143ad90ff03702a3b9c796c657f3bdaaf851ea79cb46b86d7

Sample: Available [here.](https://bazaar.abuse.ch/sample/4fa0e396cda9578143ad90ff03702a3b9c796c657f3bdaaf851ea79cb46b86d7/)


### What is this ISO about?

Before we proceed with the extraction and analysis of this malicious ISO, could you help us gain a better understanding of the ISO and its significance with a moderate level of confidence?

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/57281d21-4870-492c-8816-da8dcbad4b04)


Recently, the [Indian Government issued a tender](https://www.indiatoday.in/india/story/indian-air-force-tender-to-hal-for-su-30-mki-fighter-jets-2465944-2023-11-22)to Hindustan Aeronautics Limited, also known as HAL, for the procurement of 12 Sukhoi-30 MKI, a variant of superior fighter jets enhancing the Indian Air Force's arsenal. These jets are sourced from JSC Sukhoi Company, an aircraft manufacturer based in Moscow. As per the newspaper article, HAL was required to respond to the tender by the end of December.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/41c2e83e-145f-487f-a69c-3edaec1b0b30)

Now, we observe that the sample was initially submitted to VT on the 9th of January 2024. Therefore, with a moderate level of confidence, we can infer that the unknown threat actor is impersonating the Sukhoi Company, attempting to deceive Air Force officials into believing that this ISO contains sensitive information.
