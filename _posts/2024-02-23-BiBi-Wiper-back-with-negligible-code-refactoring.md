---
title:  "BiBiWiper: Wiper Malware back with negligible code-refactoring."
layout: post
categories: malware-analysis
---


## Table Of Contents
- Background.
- About BiBiWiper Malware.
- Metadata.
- Basic Static Analysis.
  - Part-I: Initial ITW Release[October-2023]
  - Part-II: Recent ITW Release[February-2024]
  - Comparing technical capabilities.
  - Comparing code restructure/refactoring.
- Shift in maturity.
- Victim Landscape.
- Recent Wipers & similarities.
- MITRE ATT&CK Mapping.
- YARA Rules.


## Background

Recently, while browsing Twitter or X, I came across a post from the [Symantec Threat Research team](https://twitter.com/threatintel/status/1760717307121164343?s=12). Later, [Dmitry Melikov](https://twitter.com/dmitriymelikov/status/1760815147470180809?s=48) also shared a post, both discussing a new strain or fresh campaigns involving the BiBiWiper Malware. In essence, a wiper malware, as the name implies, doesn't engage in anything extraordinary except for causing chaotic destruction by wiping and corrupting existing data on the target machines. Typically, wiper malware is crafted by threat actors aimed at creating havoc and destruction, often during times of war or political instability between states, groups or similar multiple entities. Subsequently, they may leverage the resulting chaos to gain popularity, frequently accompanied by propaganda. This blog will focus on understanding the working of both the strains of this wiper and then comparing the code refactoring, then will be mapped according to MITRE ATT&CK framework with some generic YARA Rules. 


## About BiBiWiper Malware. 

At the beginning of this blog, we agreed that wiper malware often shows up during political or geographical turmoil. Let's now figure out why this happens and understand the name given to this type of wiper malware.
