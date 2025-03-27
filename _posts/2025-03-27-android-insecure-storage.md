---
layout: post
title: Android (Insecure) Storage
date: 2025-03-27 16:11 +0200
categories: Hextree-Android-Course
tags: android hextree
---
# **Android Storage Overview**

- Shared Preferences
- Databases
- Cache Files

While the topic of [Content Providers](https://app.hextree.io/courses/content-provider) is closely related to data and file storage, we decided to place it into a separate course.

---

# **The Android Internal Storage**

Android protects the internal storage so apps can only access their own files. That also means that exploring the internal storage folders in `/data/data/<apk_path>` is only possible on a rooted phone or emulator:

```bash
# no root permissions
emu64a:/ $ ls -lah /data/data/
ls: /data/data/: Permission denied

# with root permissions
emu64a:/ $ su root
emu64a:/ # ls -lah /data/data/
total 1.3M
drwxrwx--x 178 system         system          12K 2024-08-11 17:52 .
drwxrwx--x  50 system         system         4.0K 2024-08-09 02:09 ..
drwx------   4 system         system         4.0K 2024-08-08 01:05 android
drwx------   4 u0_a53         u0_a53         4.0K 2024-08-08 01:05 android.auto_generated_rro_vendor__
drwx------   5 u0_a130        u0_a130        4.0K 2024-08-08 01:06 android.ext.services
drwx------   4 u0_a85         u0_a85         4.0K 2024-08-08 01:05 android.ext.shared
drwx------   4 u0_a131        u0_a131        4.0K 2024-08-08 01:05 com.android.adservices.api
drwx------   4 u0_a64         u0_a64         4.0K 2024-08-08 01:05 com.android.apps.tag
drwx------   4 u0_a57         u0_a57         4.0K 2024-08-08 01:05 com.android.backupconf
```

---

# **The Cache Directory**

Instead of directly assembling folder paths, the application Context provides helper functions such as [getCacheDir()](https://developer.android.com/reference/android/content/Context#getCacheDir()) to resolve the path to the application internal folder.

---

# **The ./files Directory**

By default, when creating a file with [openFileOutput()](https://developer.android.com/reference/android/content/Context#openFileOutput(java.lang.String,%20int)), a file is created in the internal storage `/data/data/<apk_name>/files/` directory. The application Context also provides a convenient function to get the files directory path using [getFilesDir()](https://developer.android.com/reference/android/content/Context#getFilesDir()).

---

# **Shared Preferences**

The [shared preferences](https://developer.android.com/training/data-storage/shared-preferences) are very convenient to store various values such as user settings.

As an app developer you might not realise that under the hood the shared preferences are actually stored in an XML file inside the `./shared_prefs/` internal storage folder. They are also often used to store access tokens or other kinds of secrets. In itself that's not an issue, but this makes shared preferences a very interesting target for stealing or overwriting internal files.

---

# **Internal Databases**

Many apps use SQLite3 to store more complex data structures in the internal storage. The android application Context offers useful functions such as [openOrCreateDatabase()](https://developer.android.com/reference/android/content/Context#openOrCreateDatabase(java.lang.String,%20int,%20android.database.sqlite.SQLiteDatabase.CursorFactory,%20android.database.DatabaseErrorHandler)) to create or access the database stored in the internal application storage.

Android should also have the `sqlite3` tool installed to interact with database files directly:

```bash
emu64a:/data/data/io.hextree.storagedemo $ sqlite3 databases/example.db
sqlite> .tables
android_metadata  example_table
sqlite> select * from example_table;
1|Hello, Database!
sqlite> PRAGMA table_info(example_table;
0|id|INTEGER|0||1
1|id|INTEGER|0||0
```

---

# **What is External Storage?**

Let's have a look at the external storage and compare it to the internal storage.

Historically the external storage was stored on a physically accessible SD card. That's why the external storage folder is called `/sdcard/`, even though on modern phones without an SD card slot it's technically also "internal phone" storage.

# **External File Access Permissions**

Back in the days, the external storage was considered "insecure", because every app could access all the data on it. Also it was easy to physically remove the SD card and steal its content. Thus you still see various tutorials and tools flagging ["use of external storage"](https://developer.android.com/privacy-and-security/risks/sensitive-data-external-storage) as an issue.

Since Android 11 the access to the "external storage" has been greatly reduced to a point where it is almost equal to protection as the internal storage. That's why you should look closely at the supported Android versions of an app, and look at the real world [version usage](https://apilevels.com/) when assessing the risk and impact of a storage related issue.

It should also be noted that various phone vendors might mess with the folder and file permissions. So you should always try to test issues related to file access on various Android versions and devices.

[Google's Mobile VRP](https://bughunters.google.com/about/rules/android-friends/6618732618186752/google-mobile-vulnerability-reward-program-rules) for example requires issues to be reproducible in latest Android version:

> Non-qualifying issues:
> 
> - [...]
> - Vulnerabilities that do not work on the latest available operating system version

This means that issues that were exploitable in old Android versions are probably not considered valid.

---

# **Scoped Storage**

Since Android 10, and especially Android 11, the [scoped storage](https://source.android.com/docs/core/storage/scoped) feature basically turned the "external storage" into a well protected storage similar to the traditional "internal storage".

> "To give users more control over their files and to limit file clutter, apps that target Android 10 (API level 29) and higher are given scoped access into external storage, or scoped storage, by default. Such apps have access only to the app-specific directory on external storage, as well as specific types of media that the app has created."
> 

We recommend you to not just blindly report apps that use external storage, but rather carefully investigate and test whether you can actually access or leak these files or not. Impact always depends on the [Android version usage](https://apilevels.com/) and what API levels an app supports.

While apps can still use the permission `MANAGE_EXTERNAL_STORAGE` on Android 13+ to request access to all files on external storage, additionally the [user must be directed to a special settings page](https://developer.android.com/training/data-storage/manage-all-files) where they have to enable "Allow access to manage all files" for the app.

---

# **Manage External Storage**

While the scoped storage heavily protects the external storage, there is still one exception. There exists the

[MANAGE_EXTERNAL_STORAGE](https://developer.android.com/training/data-storage/manage-all-files) dangerous permission that can be requested by apps to still read the external storage files. This permission is only available to apps in the Play Store with an exception, or via side-loading. Thus limiting the impact and risk a lot. Though the risk is not completely mitigated, so depending on the unique threat-model of an app, you might still want to consider a malicious app to have this permission.

---

# **Developing OmniNotes Stealer**

Give it a try on your own, but if you get stuck here is a project that already requests all the permissions you need:

**Download File:** [OmniNotesExploiter Stealer.zip](https://storage.googleapis.com/hextree_prod_image_uploads/media/uploads/insecure-storage/OmniNotesExploiter%20Stealer.zip)

On Android 10 and below, an attack app just has to request the following permissions to access the files copied by OmniNote:

```xml
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
```

However this method is deprecated and since [scoped storage](https://source.android.com/docs/core/storage/scoped)

the external storage has been much more restricted:

> READ_EXTERNAL_STORAGE is deprecated (and is not granted) when targeting Android 13+. Scoped storage is enforced on Android 10+ (or Android 11+ if using requestLegacyExternalStorage).
> 

To manage external storage in later versions, an app now has to request the `MANAGE_EXTERNAL_STORAGE` permission and redirect the user to a [special settings page](https://developer.android.com/training/data-storage/manage-all-files). However app-specific "external" files (stored within `/sdcard/Android/<com.package.name>/*`) are still not accessible with that new permission. That means this issue is not fully exploitable on Android systems with properly implemented [scoped storage](https://source.android.com/docs/core/storage/scoped).

Despite these restrictions since Android 11+, it could still be considered a minor issue worth fixing, as the functionality to copy internal files is not intentional.

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
