---
layout: post
title: Static Application Security Testing (SAST) for Xamarin Android Applications
date: 2025-03-14 23:48 +0200
categories: Mobile
tags: Android Mobile HackTheBox
---
## Introduction
Android applications come in various frameworks, including Flutter, Xamarin, Cordova, React Native, and more. In this article, I will walk you through a Static Application Security Testing (SAST) approach for a Xamarin Android application by solving an HTB challenge.
## Initial Analysis
Upon launching the application, I noticed an input field that accepts a password and validates it. Entering any random password resulted in an error message.
![](https://miro.medium.com/v2/resize:fit:1090/format:webp/1*BjI-vaePu6mbRza0iQQkYA.png)
![](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*z8tDMiAZTv9iuj8Od-33Ow.png)

## Examining the APK
By analyze the application further, I decompiled the APK using **JADX**.I found a basic `AndroidManifest.xml` file:
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*_QJWZJJtzdRjK16L2pHdMg.png)

However, searching for the validation logic in the source code did not yield immediate results. Instead, I observed multiple files and folders related to Xamarin.
![](https://miro.medium.com/v2/resize:fit:1054/format:webp/1*7Ey_nbR1_x1ZbG4vYbLlCg.png)

## Understanding Xamarin.Android Architecture
Xamarin.Android allows developers to build Android applications using C# .NET. The C# code is compiled into Intermediate Language (IL), which is then Just-In-Time (JIT) compiled to a **native assembly** when the application lucnch. Below is a rough architecture of Xamarin.Android:
- Xamarin provides `.NET` bindings to `Android.*` and `Java.*` namespaces.
- Applications run under the Mono execution environment alongside the Android Runtime (**ART**).
- Managed Callable Wrappers (**MCW**) and Android Callable Wrappers (**ACW**) facilitate communication between the Mono and ART environments.
![](https://miro.medium.com/v2/resize:fit:828/format:webp/1*XZjL4BARDkwkPriBACmvgg.png)

## Locating the Application Logic
Since the application logic is compiled into native libraries, I needed to find these files. Using `apktool`, I discovered the `.dll` files under `/unknown/assemblies`. With JADX, they were found in `resources/assemblies/`:
![](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*iC2wQ6htxGq1qq_m3wZj4Q.png)

**Note**: The challenge name is SeeTheSharpFlag, hinted at investigating `SeeTheSharpFlag.dll`.

After downloading the file, I used the `file` command in Kali Linux to inspect its type. Surprisingly, it was identified as a Sony **PlayStation Audio** file.
![](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*YnnKE1O56AjAsk8PHYJlXQ.png)

To analyze further, I ran the **xxd** command and identified a file signature corresponding to **XALZ**, which is a compressed format used in **.NET** applications.
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*WWBLY6J8Ue-CSAKMJsNrtA.png)
I then used the `xamarin-decompress` tool to decompress the library using [LZ4 block](https://github.com/NickstaDB/xamarin-decompress)
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*MatJpm1UtHS-iFIp1KBdpA.png)
After decompression, running the `file` command again revealed it as a Portable Executable 32-bit (**PE32**) file.
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*FBQggc_s3f24Gno9IwrE_Q.png)
I then opened the file using **dotPeek**, it was a .NET decompiler tool.
## Extracting the Password Validation Logic
Upon inspecting `SeeTheSharpFlag.dll` in dotPeek, I found a `MainPage` class containing a method named `Button_Clicked()`, which likely handles password validation.
![](https://miro.medium.com/v2/resize:fit:786/format:webp/1*buP9krYvxyYZvC3Mm7JmsA.png)
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*AA1rW3CZAtupfmnEh7HA-g.png)
## Here’s the extracted function:
```java
private void Button_Clicked(object sender, EventArgs e)
    {
      byte[] buffer = Convert.FromBase64String("sjAbajc4sWMUn6HJBSfQ39p2fNg2trMQ/MmTB5mno=");
      byte[] rgbKey = Convert.FromBase64String("6F+WzEp5QXoJV+iTli4Q==");
      byte[] rgbIV = Convert.FromBase64String("DZ6YaWJlZ26VmEEQ31A==");
      using (AesManaged aesManaged = new AesManaged())
      {
        using (ICryptoTransform decryptor = aesManaged.CreateDecryptor(rgbKey, rgbIV))
        {
          using (MemoryStream memoryStream = new MemoryStream(buffer))
          {
            using (CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, decryptor, CryptoStreamMode.Read))
            {
              using (StreamReader streamReader = new StreamReader((Stream) cryptoStream))
              {
                if (streamReader.ReadToEnd() == ((InputView) this.SecretInput).Text)
                  this.SecretOutput.Text = "Congratz! You found the secret message";
                else
                  this.SecretOutput.Text = "Sorry. Not correct password";
              }
            }
          }
        }
      }
    }
```
From this code, we can see that the application uses **AES** encryption to validate the password through this line:
```java
if (streamReader.ReadToEnd() == ((InputView) this.SecretInput).Text)
```
Also The decryption keys are hardcoded in the application, making it possible to decrypt the expected password.
```java
byte[] buffer = Convert.FromBase64String("sjAbajc4sWMUn6HJBSfQ39p2fNg2trMQ/MmTB5mno=");
byte[] rgbKey = Convert.FromBase64String("6F+WzEp5QXoJV+iTli4Q==");
byte[] rgbIV = Convert.FromBase64String("DZ6YaWJlZ26VmEEQ31A==");
```
## Decrypting the Password
The AES encryption used in the application employs `CBC mode` with Base64-encoded components.
Below is a Python script to decrypt the expected password:
```python
import base64
from Crypto.Cipher import AES

def decrypt_aes_cbc(ciphertext_b64, key_b64, iv_b64):
    ciphertext = base64.b64decode(ciphertext_b64)
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    decrypted = decrypted[:-pad_len]
    return decrypted.decode()

ciphertext_b64 = "sjAbajc4sWMUn6HJBSfQ39p2fNg2trMQ/MmTB5mno="
key_b64 = "6F+WzEp5QXoJV+iTli4Q=="
iv_b64 = "DZ6YaWJlZ26VmEEQ31A=="

plaintext = decrypt_aes_cbc(ciphertext_b64, key_b64, iv_b64)
print("========================")
print("==== Decrypted text:", plaintext)
print("========================")
```
## Extracting the Flag
Running the script successfully decrypted the flag.
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*gRfin3mkAasGgSCNKTaptA.png)
I then submitted it through the mobile app and received the Congratz message.
![](https://miro.medium.com/v2/resize:fit:1084/format:webp/1*1OAT1ZSQKtEJXbA6pcBRiQ.png)

## Conclusion
This challenge demonstrated how to analyze and reverse-engineer Xamarin applications using SAST techniques. By understanding Xamarin’s architecture and extracting native libraries.

For further reading, I highly recommend **Akshay Shinde’s** blog post on [Xamarin Reverse Engineering](https://www.appknox.com/blog/xamarin-reverse-engineering-a-guide-for-penetration-testers).

**THANKS FOR READING ❤️**
