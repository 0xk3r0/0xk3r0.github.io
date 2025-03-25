---
layout: post
title: 'HackTheBox: APKey Mobile Challenge'
date: 2025-03-14 23:09 +0200
categories: Mobile
tags: Android Mobile HackTheBox
---
Editing Smali code is a powerful technique in reverse engineering. In this write-up, I will solve the **HTB APKey** challenge by modifying its Smali code.
## What is Smali Code?
Smali code represents the intermediate language of Android application bytecode. When Android apps are compiled from Java/Kotlin source code, they are translated into bytecode, which can then be converted into Smali code — a readable format that allows us to examine an app’s functionality and behavior. By mastering Smali code, you gain valuable insight into an app’s logic, proprietary algorithms, and its interactions with the Android system.
## Diving into the Challenge
First, I downloaded the challenge’s zip file, extracted it, and obtained the ذ file. I then installed it on an emulator and also opened it using **JADX**, which converts complex bytecode into more readable Java code.
### Step 1: Analyzing the Login Mechanism
When I launched the application, I encountered a login page. I attempted a default login using `admin:admin`, but it displayed the error message:
**“Wrong Credentials!”**
![](https://miro.medium.com/v2/resize:fit:828/format:webp/1*Y7Q6swLBsfHF-1lv3tz6zQ.png)
To investigate further, I searched for this error message within the decompiled Java code using **JADX**. I found it inside the `onClick` method of the `MainActivity` class:
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*s5Qu0LU0v1UPSX6Pf18_Hw.png)
```java
   public void onClick(View view) {
            Toast makeText;
            String str;
            try {
                if (MainActivity.this.f928c.getText().toString().equals("admin")) {
                    MainActivity mainActivity = MainActivity.this;
                    b bVar = mainActivity.e;
                    String obj = mainActivity.d.getText().toString();
                    try {
                        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                        messageDigest.update(obj.getBytes());
                        byte[] digest = messageDigest.digest();
                        StringBuffer stringBuffer = new StringBuffer();
                        for (byte b2 : digest) {
                            stringBuffer.append(Integer.toHexString(b2 & 255));
                        }
                        str = stringBuffer.toString();
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                        str = "";
                    }
                    if (str.equals("a2a3d412e92d896134d9c9126d756f")) {
                        Context applicationContext = MainActivity.this.getApplicationContext();
                        MainActivity mainActivity2 = MainActivity.this;
                        b bVar2 = mainActivity2.e;
                        g gVar = mainActivity2.f;
                        makeText = Toast.makeText(applicationContext, b.a(g.a()), 1);
                        makeText.show();
                    }
                }
                makeText = Toast.makeText(MainActivity.this.getApplicationContext(), "Wrong Credentials!", 0);
                makeText.show();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
    }
```
From this analysis, I discovered that:
- The app uses `"admin"` as a hardcoded username.
- It hashes the entered password using **MD5** and compares it with the stored hash: `a2a3d412e92d896134d9c9126d756f`.

### Step 2: Attempting to Crack the Hash
I attempted to crack this hash using different methods, but I was unable to find a valid plaintext password.
### Step 3: Modifying the Smali Code
Since cracking the hash wasn’t successful, I decided to modify the Smali code directly.
**Decompiling the APK**
To achieve this, I used **APKTool** to decompile the APK:
```bash
java -jar apktool_2.11.0.jar d APKey.apk
```
After decompilation, I searched within the Smali files for the `MainActivity` class and located the hash value.
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*In8dxgicy5OycDWtlmVgqA.png)
Before modifying it, I calculated the MD5 hash for my own password (e.g., `kero`) and obtained a new hash. I then replaced the original hash in the Smali code with my new hash.
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*0yHwY7bkQ5ujTAyrTA-Bew.png)
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*TuM2WMZyCUCceA2vqeYH6A.png)
### Step 4: Recompiling & Signing the APK
After making the necessary modifications, I rebuilt the APK using the same tool:
```bash
java -jar apktool_2.11.0.jar b APKey
```
Since Android requires signed APKs for installation.<br> I signed and aligned the modified APK using **Uber APK Signer**:
```bash
java -jar uber-apk-signer.jar -a APKey/dist/APKey.apk
```
Next, I uninstalled the original application and installed the newly modified version.
### Step 5: Bypassing Authentication & Getting the Flag
After launching the modified app, I entered the new credentials based on my altered hash. This time, authentication was **successful**, and I retrieved the flag! 🎉
![](https://miro.medium.com/v2/resize:fit:1036/format:webp/1*45GxG7g1M9vgenMLPGCUsA.png)

Successfully obtained the flag and submitted it to the HTB challenge.
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*vi5bPHrRGSCvXNiaQXYF9g.png)

**THANKS FOR READING ❤️**

<script src="https://giscus.app/client.js"
        data-repo="0xk3r0/0xk3r0.github.io"
        data-repo-id="R_kgDOOGw3bQ"
        data-category="General"
        data-category-id="DIC_kwDOOGw3bc4CobRY"
        data-mapping="pathname"
        data-strict="0"
        data-reactions-enabled="1"
        data-emit-metadata="0"
        data-input-position="bottom"
        data-theme="dark"
        data-lang="en"
        crossorigin="anonymous"
        async>
</script>
