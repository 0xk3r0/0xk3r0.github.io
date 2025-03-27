---
layout: post
title: Managing apps using adb
date: 2025-03-27 01:37 +0200
categories: Hextree-Android-Course
tags: android hextree
---
```powershell
adb install <path to .apk>
```

Using adb install we can manually install packages using the command line.

```powershell
adb shell pm list packages
```

Lists all installed packages - including system packages.

```powershell
adb shell pm list packages -3
```

List only third party packages.

```powershell
adb shell pm clear <package_name>
```

Clear the application data without removing the actual application.

```powershell
adb shell dumpsys package <package_name>
```

List information such as activities and permissions of a package.

```powershell
adb shell am start <package_name>/<activity_name
```

Starts the activity of the specified package.

```powershell
adb uninstall <package_name>
```

Uninstalls the specified application.

# **adb push**

To transfer files between our computer and the device, we use the commands adb push and adb pull.

```powershell
adb push <local_file_on_computer> <target_path_on_device>
```

With `adb push` we can push a file or a directory from our computer to the device. We have to specify a destination path - a common one is `/sdcard/`, which is not an external SD-card, but generally mounts to the internal storage of the device.

Example to push test.png from the Desktop to the Download folder of the device:

```powershell
adb push Desktop/test.png /sdcard/Downloads/
```

# **adb pull**

```powershell
adb pull <file_path_on_device> [<optional_target path_on_the_computer>]
```

With `adb pull` we can pull files from the device to the computer. For example, to download the entire Download folder from the device, we can use:

```powershell
adb pull /sdcard/Downloads
```

This will store Downloads in your current directory.

Note that with `adb pull` we can only access the files we have access to with `adb shell`, and so you will find that you can not download a lot of application files this way.

# **adb logcat**

```powershell
adb logcat -v <log_format>
```

Change the log format - for example using `brief` to get a more condensed version of the log.

# **Log Filtering**

In some cases there can be lots of log entries which makes it hard to focus on the things that matter. For example if you are only interested in the logs produced by the `MainActivity`, you can use a log filter for that:

```powershell
adb logcat "MainActivity:V *:S"
```

Filter format:

- `MainActivity:V` ensures that logs from the tag MainActivity with a severity of Verbose and above are logged
- `:S` Ensures that all other Tags are ignored (as nothing will log with log-level Silent or above)

Logging severities:

|  | Log level |
| --- | --- |
| V | Verbose |
| D | Debug |
| I | Info |
| W | Warning |
| E | Error |
| F | Fatal |
| S | Silent |

You can find the full documentation for pm [here](https://developer.android.com/tools/adb#pm).

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
