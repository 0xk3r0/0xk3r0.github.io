---
layout: post
title: Android Permissions
date: 2025-03-27 16:13 +0200
categories: Hextree-Android-Course
tags: android hextree
---
# **Exported vs. Non-Exported Components**

The strongest protection against malicious apps, is to simply not export any components. But the attribute `android:exported="false"` is not the only way to protect components such as activities or services.

---

# **Normal System Permissions**

There exist several [`protectionLevel`](https://developer.android.com/guide/topics/manifest/permission-element) for permissions, but let's focus only on the "normal" permission for now.

The normal permission is described like this:

> "[This is the] default value. A lower-risk permission that gives requesting applications access to isolated application-level features with minimal risk to other applications, the system, or the user. The system automatically grants this type of permission to a requesting application at installation, without asking for the user's explicit approval, though the user always has the option to review these permissions before installing."
> 

Also have a look at the Android core [AndroidManifest.xml](https://android.googlesource.com/platform/frameworks/base.git/+/refs/heads/main/core/res/AndroidManifest.xml) for a huge list of default permissions.

---

# **Dangerous System Permissions**

The "dangerous" [`protectionLevel`](https://developer.android.com/guide/topics/manifest/permission-element) is used for more critical actions. It also results in asking the user for explicit consent.

The dangerous permission is described like this:

> "A higher-risk permission that gives a requesting application access to private user data or control over the device that can negatively impact the user. Because this type of permission introduces potential risk, the system might not automatically grant it to the requesting application. For example, any dangerous permissions requested by an application might be displayed to the user and require confirmation before proceeding, or some other approach might be taken to avoid the user automatically granting the use of such facilities."
> 

Also have a look at the Android core [AndroidManifest.xml](https://android.googlesource.com/platform/frameworks/base.git/+/refs/heads/main/core/res/AndroidManifest.xml) for a huge list of default permissions.

---

# **Security Boundaries of Permissions**

Generally you can assume that your attacker app can request any "normal" permission without making your attack invalid. In general always attack upwards - meaning that your attack app should require a lot less permissions than the exploit gives you.

---

# **Identify Valuable Targets via Permissions**

The system permissions such as `system` or `internal` are permissions that we as an attacker cannot get. BUT by looking for apps that use them, we can identify very valuable targets.

---

# **Protecting Components with Permissions**

Exported components such as activities and services can add an additional permission attribute to restrict the apps that can reach you. For example a weather app that provides a service with weather information, could protect its service so that only apps that also have the GPS permission can access it:

```xml
<service android:name="com.example.weather.WeatherService"
         android:permission="android.permission.ACCESS_FINE_LOCATION"
         android:exported="true">
</service>
```

---

# **Creating Custom Permissions**

Besides using system permissions, applications can also create their own permissions in their `AndroidManifest.xml`.

[Termux](https://play.google.com/store/apps/details?id=com.termux&hl=en) for example declares a dangerous permission that can be used to execute arbitrary code.

```xml
<permission android:label="@string/permission_run_command_label"
    android:icon="@mipmap/ic_launcher"
    android:name="com.termux.permission.RUN_COMMAND"
    android:protectionLevel="dangerous"
    android:description="@string/permission_run_command_description"/>

```

If another app wants to use Termux to run code, it has to request the `RUN_COMMAND` permission, which triggers an explicit consent dialog.

---

# **Protected Broadcasts**

Besides the permissions, the Android core [`AndroidManifest.xml`](https://android.googlesource.com/platform/frameworks/base.git/+/refs/heads/main/core/res/AndroidManifest.xml) also contains lots of protected broadcasts. No regular app is allowed to send these broadcasts to other apps.

```xml
// [...]
<protected-broadcast android:name="android.intent.action.BOOT_COMPLETED" />
<protected-broadcast android:name="android.intent.action.PACKAGE_INSTALL" />
<protected-broadcast android:name="android.intent.action.PACKAGE_ADDED" />
<protected-broadcast android:name="android.intent.action.PACKAGE_REPLACED" />
// [...]

```

Pro Tip: you can also use the [Android Code Search](https://cs.android.com/) to look for any log message or exception reason, to learn more about the implementation details of certain Android features.

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

