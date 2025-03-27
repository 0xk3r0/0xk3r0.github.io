---
layout: post
title: Reverse Engineering Android Apps
date: 2025-03-27 01:50 +0200
categories: Hextree-Android-Course
tags: android hextree
---
# **1- Getting APKs from a device**

First, find the package name of the application you want to download. You can list all third-party packages using:

```powershell
adb shell pm list packages -3
```

Next, we have to get the path to the APK. This can be done using:

```powershell
adb shell pm path <package_name>
```

Now we can just pull the APK from the phone:

```powershell
adb pull <path_to_apk>
```

2- Using `apktool d <path_to_apk>` we can extract APKs.

Note that apktool will not just simply extract the .zip of the .apk: It will also "baksmali" (disassemble) the embedded classes into smali bytecode.

You can also explore the `AndroidManifest.xml` to see what activities & more the app exposes.


When you see that is there exported activity try to start it direct using adb:

```powershell
adb shell am start <package-name>/.<activity-name>
```


3- When you edit in any file such as `Androidmainfest.xml`  for example you edit activity to make it **exported, you must align and sign this apk using `uber-apk-signer` :**
1. apktool d <.apk>
2. make your edit in the apk folder 
3. open this folder and run this: apktool b
4. then run this: java -jar uber-apk-signer.jar -a /path/to/apk

4- Strings in Android applications are often not hard-coded, but instead packed into resources. If you see code such as `R.id` or `R.string` it means that a resource is loaded from the resource directory or the `resources.asrc` file.

This highlight the id for string “secret2”: 

![](/Images/hextreeCourseImages/image1.png)

you can search by string or by their id:

![](/Images/hextreeCourseImages/image2.png)

5- Some applications will use functions implemented in native shared objects. You can identify calls into such functions by the keyword `native`.

This functionality is called JNI - Java Native Interface. Jadx does not let us decompile shared objects, instead we need to use tools such as Binary Ninja or Ghidra. You won't have to do that for this secret though - using a tool such as `strings` should be enough to find the password!:

![](/Images/hextreeCourseImages/image3.png)

6- If application Used API to request data try intercept  this action and see what can do with this API.

Try to read the source code if this API key loaded from native library —> .so and search about it using `Ghidra` or `Strings` Tool in linux.

7- If the application has updated version their is extension in vscode to compare changes in two versions:  

[Compare Folders](https://marketplace.visualstudio.com/items?itemName=moshfeu.compare-folders) extension for Visual Studio Code to check the differences between the original Hextree Weather app and another updated version. This allows us to quickly navigate differences between the two applications.

We use the jadx CLI to decompile the original and the updated APK into two different folders, and then compare them in VS Code.

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

