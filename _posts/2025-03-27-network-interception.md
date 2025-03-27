---
layout: post
title: Network Interception
date: 2025-03-27 02:02 +0200
categories: Hextree-Android-Course
tags: android hextree
---
## **Installing Certificate in User Store:**

In order to be able to intercept TLS/SSL communication, we need the certificate of our proxy tool to be trusted by the device. Via the android settings we can easily install a certificate into the "user" CA store.

User certificates are only trusted by apps when:

1. The app targets Android 6 (API level 23) or lower
2. Or [network security config](https://developer.android.com/privacy-and-security/security-config) specifically includes "user" certs

Example `xml/network_security_config.xml` which trusts "user" certificates:

```xml
<base-config cleartextTrafficPermitted="false">
    <trust-anchors>
        <certificates src="system" />
        <certificates src="user" />
    </trust-anchors>
</base-config>
```

# **Threat Model Notes**

When an app sends cleartext `http://` traffic we can probably consider this to be a security issue. However traffic that can only be intercepted with a purposely installed certificate is not an issue. By installing a CA we are intentionally "weakening" the security of the device to allow us to decrypt the traffic.

---

Due to the default [network security config](https://developer.android.com/privacy-and-security/security-config) rules, most apps only trust "system" certificates. The default configuration for apps targeting Android 9 (API level 28) and higher is as follows:

```xml
<base-config cleartextTrafficPermitted="false">
    <trust-anchors>
        <certificates src="system" />
    </trust-anchors>
</base-config>

```

# **Rooted Device**

In order to install our certificate into the system store, root access is required. Thus for this method you require a [rooted physical phone](https://www.google.com/search?q=how+to+root+my+android+phone), [rooted emulator](https://www.google.com/search?q=rooting+android+14+emulator) or use a non-Google emulator image that allows root access.

# **Install System Certificate**

If you have a device with root access follow the following steps:

1. Install the proxy certificate as a regular user certificate
2. Ensure you are root (`adb root`), and execute the following commands in `adb shell`:

```bash
# Backup the existing system certificates to the user certs folder
cp /system/etc/security/cacerts/* /data/misc/user/0/cacerts-added/

# Create the in-memory mount on top of the system certs folder
mount -t tmpfs tmpfs /system/etc/security/cacerts

# copy all system certs and our user cert into the tmpfs system certs folder
cp /data/misc/user/0/cacerts-added/* /system/etc/security/cacerts/

# Fix any permissions & selinux context labels
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*
```

---

There have been [significant changes](https://httptoolkit.com/blog/android-14-breaks-system-certificate-installation/) in Android 14 in the way how the system certificates are handled.

# **Install System Certs on Android 14**

This method also requires root access. First install your proxy certificate as a regular user cert. Then run the following script created by Tim Perry from [HTTP Toolkit](https://httptoolkit.com/blog/android-14-install-system-ca-certificate/):

```bash
# Create a separate temp directory, to hold the current certificates
# Otherwise, when we add the mount we can't read the current certs anymore.
mkdir -p -m 700 /data/local/tmp/tmp-ca-copy

# Copy out the existing certificates
cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/tmp-ca-copy/

# Create the in-memory mount on top of the system certs folder
mount -t tmpfs tmpfs /system/etc/security/cacerts

# Copy the existing certs back into the tmpfs, so we keep trusting them
mv /data/local/tmp/tmp-ca-copy/* /system/etc/security/cacerts/

# Copy our new cert in, so we trust that too
cp /data/misc/user/0/cacerts-added/* /system/etc/security/cacerts/

# Update the perms & selinux context labels
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*

# Deal with the APEX overrides, which need injecting into each namespace:

# First we get the Zygote process(es), which launch each app
ZYGOTE_PID=$(pidof zygote || true)
ZYGOTE64_PID=$(pidof zygote64 || true)
# N.b. some devices appear to have both!

# Apps inherit the Zygote's mounts at startup, so we inject here to ensure
# all newly started apps will see these certs straight away:
for Z_PID in "$ZYGOTE_PID" "$ZYGOTE64_PID"; do
    if [ -n "$Z_PID" ]; then
        nsenter --mount=/proc/$Z_PID/ns/mnt -- \
            /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
    fi
done

# Then we inject the mount into all already running apps, so they
# too see these CA certs immediately:

# Get the PID of every process whose parent is one of the Zygotes:
APP_PIDS=$(
    echo "$ZYGOTE_PID $ZYGOTE64_PID" | \
    xargs -n1 ps -o 'PID' -P | \
    grep -v PID
)

# Inject into the mount namespace of each of those apps:
for PID in $APP_PIDS; do
    nsenter --mount=/proc/$PID/ns/mnt -- \
        /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts &
done
wait # Launched in parallel - wait for completion here

echo "System certificate injected"
```

The [HTTP Toolkit](https://httptoolkit.com/docs/guides/android/#the-android-app) also offers a convenient single-click solution, which simply executes the above steps automatically.

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
