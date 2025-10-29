---
layout: post
title: "Do you think bypassing SSL pinning can get you a bounty?"
date: 2025-10-20 21:54 +0300
categories: Mobile-Security
tags: android
---

In a recent bug bounty program, I came across two interesting vulnerabilities in a mobile application. Each presented a unique challenge and a valuable learning experience.
![](/Images/10.png)

## 1. Sensitive Log Vulnerability
The first issue was a Sensitive Log Vulnerability — something I’ve noticed to be surprisingly common in many applications. Despite its frequency, this vulnerability can be highly critical depending on the type of business and the nature of the data being logged.

To identify it effectively during static analysis, I recorded normal activity in the app using a valid email and password, then downloaded the full directory of the application. From there, I searched for the entered data using tools like:
- `Regex` (in any code editor)
- `grep` on Linux
- `Select-String` on Windows

This process helps reveal whether sensitive user data (such as credentials or tokens) is being written to logs — a mistake that could lead to major privacy or security issues.

## 2. Certificate Pinning Bypass
The second vulnerability was more complex — a certificate pinning bypass. Initially, I found it strange that the program’s policy explicitly allowed this kind of bypass, but once I started working on it, I understood why. It turned out to be one of the most challenging bypass scenarios I’ve dealt with.

The app was built using Flutter, combined with other technologies, making traditional bypass methods ineffective. After experimenting with multiple approaches, I came across a helpful blog post by **Eng. Hatem Mohamed**, which discussed various Flutter bypass methods.

I found that while each method was useful individually, the real breakthrough came from combining two techniques:

1. **DNS-based Redirection**, and
2. A **custom Frida script** that hooks into a specific function validating the app’s certificate PINs.

This combination finally worked, and I was able to successfully validate the bypass. Huge thanks to Eng. Hatem for sharing his work — it was invaluable

If you’d like to dive deeper into the technical side of this method, you can check out his blog post [here](https://cylent.net/mastering-https-traffic-interception-in-flutter-using-burp-suite-13c02b968bf4).
<br>(See method number 4)

**Thanks for reading ❤️**
