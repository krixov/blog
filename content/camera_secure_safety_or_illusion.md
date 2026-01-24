---
title: "Security Cameras: Safety or Illusion?"
cover: https://hackmd.io/_uploads/HkMSwoZ81l.png
date: 2024-01-01T01:00:00-07:00
lastmod: 2024-01-01T01:00:00-07:00
tags: ["Trick", "Security"]
categories: ["IoT"]
---

> Hey everyone, today I want to share a bit about my family's camera system - installed since 2018 with nearly 10 old units and a few newer models. The "newer" ones are better because they have modern features like viewing through apps, two-way communication, and are completely separate from the old models that only know how to record through cables.

## How did the story begin?
That day I was sick, lying around at home, so bored I was looking everywhere. Then I noticed the camera mounted on the wall. The amber light was still on, meaning it was still working, but no one in the family had used it anymore, probably for a few years now. Suddenly I thought: *If I were an outsider, just by getting into my home's Wi-Fi, could I hack these cameras?* So I started exploring right away.

![image](https://hackmd.io/_uploads/BkFC3EW8Jl.png)

## Discovering the system: XVR DVR
My family uses an `XVR` recorder - a type of `Hybrid DVR (Digital Video Recorder)`, specialized for storing data from the old cameras.

![image](https://hackmd.io/_uploads/rkWxqlu2yl.png)

These devices need power cables and another cable to transmit data to the XVR. From the XVR, it outputs video to a separate monitor, plays back recordings, or does other miscellaneous tasks. The newer cameras don't need XVR - they push data directly to the cloud, but today I'm focusing only on the older models.

![image](https://hackmd.io/_uploads/r1t6Qsb81g.png)

## Network scanning and "detecting" XVR

Since my target was only that XVR device, and by default these XVR devices all open an `HTTP` port --> My idea was to scan the entire network to find devices that could be XVRs.

After some scanning, I discovered a device with `RTSP (Real-Time Streaming Protocol)` open - a protocol commonly used for real-time data transmission --> Based on this, I identified this as the XVR recorder. The newer cameras weren't showing up because they send everything directly to the cloud :>.

![image](https://hackmd.io/_uploads/BywV4iZIkg.png)

## Web Interface - the first entry point
At first glance, there was `HTTP` on this IP, and when I tried accessing it, I found it was just a Plugin download page, probably not important.

![image](https://hackmd.io/_uploads/rydn54ZUkl.png)

In my opinion, this Plugin file doesn't have any purpose other than supplementing web browsers.

![image](https://hackmd.io/_uploads/BkjTOdWLyl.png)

When I opened the page source code (Ctrl + U), I saw a bunch of Chinese comments - strange really, camera bought in Vietnam but the code was Chinese.

![image](https://hackmd.io/_uploads/HkV58FZUJg.png)

However, that `Login.htm` path couldn't be ignored.

![image](https://hackmd.io/_uploads/BybaUFZI1l.png)

After some Googling, I found documentation for a similar receiver: [QDVR161701P.pdf](https://manuales.qian.mx/QDVR161701P.pdf).

![image](https://hackmd.io/_uploads/BkfHDY-UJx.png)

It seems like Vietnam's receivers were "inspired" by these guys. After referring to the documentation, I found that the receiver's admin account would have the username `admin`.

![image](https://hackmd.io/_uploads/r1Szm5bLJg.png)

And the `password`? With 6 digits, bruteforce is quite simple, not too difficult since the payload doesn't require any authentication, just a matter of time!

![image](https://hackmd.io/_uploads/Sykr-9b8ye.png)

And luckily, I found the password after a not-too-long period of time (my family didn't remember the password anymore since we didn't use it).

![image](https://hackmd.io/_uploads/rkdF-cb8yx.png)

All 8 cameras from this receiver couldn't be viewed directly on the web because no plugin supported it, even though I tried running that `webclient` file.

After some frantic Googling and ChatGPT-ing, I found [Pale Moon](https://www.palemoon.org/) (a browser forked from `Firefox` that still supports `NPAPI`) would help me view them.

However, at this point it wasn't saying the plugin wasn't supported anymore, but instead switched to a black screen state...

![image](https://hackmd.io/_uploads/ryIXfcbIkx.png)
## Direct access via RTSP
If that's the case, there's still one way I forgot - directly connecting to the receiver's stream using RTSP (port 554)

Normally people think connecting to cameras through VLC or ffplay is very simple, right? Something like: `rtsp://username:passwd@ip:port/streamabcdef` or something like that, but no :))). All wrong!

![image](https://hackmd.io/_uploads/r16d45Z81e.png)

It was like trying to guess the path but none worked, so I went digging through all the information and documentation for this device and found:

![image](https://hackmd.io/_uploads/S1UVJo-Lyl.png)

In conclusion, the RTSP format to connect to this device will be:

`rtsp://ip:port/user=xxx&password=xxx&channel=xx&stream=x.sdp`

- `channel`: The camera number (1, 2, 3...).
- `stream`: 0 is the main stream, 1 is the sub-stream.

I tried immediately with my home IP:
`rtsp://192.168.1.108:554/user=admin&password=[my-password]&channel=05&stream=0.sdp`

Opened VLC, entered the link, and boom - the camera image appeared immediately. From here, whether I want to use VLC, ffplay, or anything else, I can view all 8 old cameras perfectly!

![image](https://hackmd.io/_uploads/H12DmiZUJg.png)

## What's scary about this?
Think about it, just by knowing my home's Wi-Fi, someone could view almost all the cameras in my house. I managed to do this in just a few hours, and I'm not even a professional hacker. If someone had malicious intentions, everything would be even easier.

## The reality from this experience
Although it looks like I'm just kicking the ball around myself, the problem is that this system isn't low-key enough for others not to find information about it. Just by getting into the Wi-Fi, without any impressive skills, you can see everything the cameras record. Old security cameras like this are really weak in security. After trying this, I felt a bit scared because my family has these devices everywhere, from the living room to the backyard.

The newer cameras are better because they push data to the cloud with proper encryption. But with the old ones connected through XVR, the vulnerability lies right in the local network. Anyone with the Wi-Fi password can see almost everything.

## How to be safer?
After this incident, I've learned a few things to share with everyone:
- **Update firmware**: If devices are too old and no longer receive updates, you should replace them. Leaving them as is is very dangerous.
- **Change default usernames/passwords**: Don't keep defaults like `admin/12345` or other easy-to-guess combinations.
- **Protect your Wi-Fi**: Use long, complex Wi-Fi passwords, newer Wi-Fi standards, and don't let too many unknown devices connect to your home network.
- **Disconnect if not in use**: Like in my home, if no one is watching anymore, it's best to unplug the old cameras for safety.

## Conclusion
From noticing the camera on the wall to being able to view its footage, I only spent a few hours. And yet my family has been thinking this system was safe for so long. Security cameras are indeed like a double-edged sword - they protect you, but if you're not careful, they can become tools for others.

Everyone remember to carefully check your camera devices! See You!
