---
layout: post
title: Hack Application Pattern Lock
date: 2025-03-11 16:55 +0200
categories: Mobile 
tags: Android-Hacking Mobile
---

Is locking your phone or any application using a pattern lock truly safe from cracking?
The answer is **NO**. Many apps use pattern locks, but these can have security misconfigurations in their authentication process. Let me explain how this works and show an example of how such an app could be compromised.

![](https://miro.medium.com/v2/resize:fit:640/format:webp/1*-TrGw6ODvmp0ODcncu4GmQ.png)

## How Pattern Lock Authentication Works

When you set a pattern lock, the pattern usually follows a 3x3 grid, which means there are 9 points:

![](https://miro.medium.com/v2/resize:fit:560/format:webp/1*5Lw489va3TPp9KARlGJ2Og.png)

For example, if your pattern goes through the points `1-> 4 -> 7 -> 3 -> 5`, the authentication system generates a SHA1 hash of the sequence. In this case, the SHA1 hash would be computed from the string `\x01\x04\x07\x03\x05`.

![](https://miro.medium.com/v2/resize:fit:640/format:webp/1*dHai5WTc-g6GDD5VWVx30w.png)

## Security Misconfigurations

There are two common security flaws related to pattern lock apps:

1. Where is the key stored? Is it stored in a safe location?
2. What kind of encryption algorithm is used? Is it easy to crack?

Let's move on to hacking an application using this method.

## Step-by-Step: Hacking a Pattern Lock Application

### 1. Create a pattern

First, set a pattern on the app. Then, gain shell access to the device: 
```bash
adb shell
```
### 2. Navigate to the app's data directory

Go to the application's path inside the /data/data directory: 
```bash
cd /data/data/<app-name>
```
### 3. List the app content

Once you found the shared-prefs directory, list the contents of the dir: `cat *`

![](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*vCGyfdn3P-CcEGE-sWZq8A.png)

If you take a look at the content of this directory file, you will find a juice string variable with the name: `image_loack_pattern` and this variable contains an encryption key:

![](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*_2F64jmkxiPgHjX71RSrYw.png)

### 4. Working on the key

This key appears to be base64 encoded; let's first decode it and store the result in the file called `pattern.key`: 
```bash
echo "7Vqqb3mCYnWOLYeMip0Bl9PPF7s=" | base64 -d > pattern.key
```
### 5. Crack the pattern

To crack the key and retrieve the pattern, use a Python tool designed to crack Android pattern locks. Run the tool on the pattern.key file:

I use this tool: [A little Python tool to crack the Pattern Lock on Android devices](https://github.com/sch3m4/androidpatternlock)

Note: If this tool is not working on python, try using python2: 
```bash
python2 aplc.py pattern.key
```

![](https://miro.medium.com/v2/resize:fit:640/format:webp/1*DtFzZG0u0OXbkG5eLng09g.png)

Now you can draw the pattern as shown by the tool (e.g., from point 1 to 5) and unlock the application!

**THANKS FOR READING ❤️**


