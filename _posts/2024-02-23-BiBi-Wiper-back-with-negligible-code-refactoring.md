---
title:  "BiBiWiper: Wiper Malware back after negligible code-refactoring."
layout: post
categories: malware-analysis
---


### Table Of Contents
- Background.
- About BiBiWiper Malware.
- Metadata.
- Technical Analysis.
  - Part-I: Initial ITW Release[October-2023]
  - Part-II: Recent ITW Release[February-2024]
  - Comparing technical capabilities.
  - Comparing code restructure/refactoring.
- Shift in maturity.
- Victim Landscape.
- Recent Wipers & similarities.
- MITRE ATT&CK Mapping.
- YARA Rules.


### Background



![Symantec-TI](https://github.com/xelemental/xelemental.github.io/assets/49472311/5841a8bc-e3f3-46b4-ac45-dfe07deebfb0)

![Dmitry](https://github.com/xelemental/xelemental.github.io/assets/49472311/b1d9178f-34b5-43e9-84e5-e7671f3c3937)





Recently, while browsing Twitter or X, I came across a post from the [Symantec Threat Research team](https://twitter.com/threatintel/status/1760717307121164343?s=12). Later, [Dmitry Melikov](https://twitter.com/dmitriymelikov/status/1760815147470180809?s=48) also shared a post, both discussing a new strain or fresh campaigns involving the BiBiWiper Malware. In essence, a wiper malware, as the name implies, doesn't engage in anything extraordinary except for causing chaotic destruction by wiping and corrupting existing data on the target machines. Typically, wiper malware is crafted by threat actors aimed at creating havoc and destruction, often during times of war or political instability between states, groups or similar multiple entities. Subsequently, they may leverage the resulting chaos to gain popularity, frequently accompanied by propaganda. This blog will focus on understanding the working of both the strains of this wiper and then comparing the code refactoring, then will be mapped according to MITRE ATT&CK framework with some generic YARA Rules. 


### About BiBiWiper Malware. 

At the beginning of this blog, we agreed that wiper malware often shows up during political or geographical turmoil. Let's now figure out behind this and understand the name given to this wiper malware.

The name "BiBiWiper" derives from the nickname of the Prime Minister of Israel, [Benjamin Netanyahu](https://en.wikipedia.org/wiki/Benjamin_Netanyahu). Given the ongoing turmoil between Israel and various separatist organizations like PIJ, Harakat al-Muqawama al-Islamiya, and others, the connection & relation becomes apparent. This unrest has deep roots and has been fueled by diverse political beliefs, leading to a [devastating incident in Israel](https://en.wikipedia.org/wiki/2023_Hamas-led_attack_on_Israel) in 2023, contributing to turbulent conditions.

In the realm of cyberspace, the notoriety of these groups also plays a substantial role. Initially developed and deployed by Hamas or Harakat al-Muqawama al-Islamiya's cyber department, BiBiWiper targeted Linux systems, as reported by SecurityJoes, a security vendor. Subsequently, it was discovered that the wiper also targeted Windows systems, affecting various business industries based in Israel. Recently, a new strain or variant of BiBiWiper has been identified, representing a rewrite of the original wiper, with a continued focus on the same domain of victims.

The unmasking of cyber operations focused on Hamas is unfortunately limited in this blog post, but if you want to read and know more about them, I would suggest going through Recorded Future's [article on infrastructure overlap](https://www.recordedfuture.com/hamas-application-infrastructure-reveals-possible-overlap-tag-63-iranian-threat-activity) between Hamas & Iranian Threat Actors, also this [article](https://www.atlanticcouncil.org/in-depth-research-reports/report/the-cyber-strategy-and-operations-of-hamas-green-flags-and-green-hats/) by Simon Handler. 
