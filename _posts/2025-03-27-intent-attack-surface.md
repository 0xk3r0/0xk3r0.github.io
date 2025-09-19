---
layout: post
title: Intent Attack Surface
date: 2025-03-27 15:25 +0200
categories: Hextree-Android-Course
tags: android hextree
---
The development documentation for [Activity](https://developer.android.com/reference/android/app/Activity) explains it like this:

> "An activity is a single, focused thing that the user can do. Almost all activities interact with the user, so the Activity class takes care of creating a window for you in which you can place your UI"
> 

When you open an app on your phone, any screen you can see has an Activity behind it, and it turns out that other apps can sometimes interact with these activities as well.

# **Attack Surface**

In order to attack an app, we need to understand what can we even interact with. That's why we should look at the `AndroidManifest.xml` and look for any `<activity>` with the `android:exported="true"` attribute.

---

# **What are Intents?**

Here is how the official documentation describes [Intent](https://developer.android.com/reference/android/content/Intent):

> "An intent is an abstract description of an operation to be performed."
> 

But a more intuitive description could be: *"Declaring an intention to do something, and let Android figure out the app that can handle it"*

# **Starting Activities**

Activities are responsible to render the screen of an app. So if your app has multiple screens, you can use `startActivity()` to start another activity. To do that you have to create an Intent object and target a specific activity class.

```java
Intent intent = new Intent();
intent.setComponent(new ComponentName("io.hextree.activitiestest", "io.hextree.activitiestest.SecondActivity"));
startActivity(intent);
```

An alternative syntax to specify the target package and activity is also:

```java
Intent intent = new Intent();
intent.setClassName("io.hextree.activitiestest", "io.hextree.activitiestest.SecondActivity");
startActivity(intent);
```

An app can always start any of its own activities, but in order to allow other apps to start your activity, they have to be exported. There is also one exported activity by default, which is the "launcher activity" that is used as a main entry point into the app. This allows the home screen or launcher application to start your app when you click it.

---

# **Incoming Intent**

The intent object that was used to start an activity, is available to the app via `getIntent()`. This feature is used to pass data to other apps, and thus it becomes a major attack surface. Does the app handle the incoming intent securely?

---

# Intent Redirect

The "**Intent Redirect**" vulnerability class is pretty simple. It means an attacker can control the intent used by the other app to for example start an activity.

If you see like this pattern of code:

Intent inside intent and passed to `startActivity()` function, it should be vulnerable 

![](/Images/hextreeCourseImages/image4.png)


# **Returning Activity Results**
Starting activities is not just a one-way communication. Activities can also return a result back to the caller when it was started with `startActivityForResult()`. Using the Intent Attack Surface app we can practice this feature.

```java
public class HextreeMainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Intent intent = getIntent();
        Utils.showDialog(this, intent);

        ((Button) findViewById(R.id.btn_launch_activity)).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent();
                intent.setComponent(new ComponentName(
                        "io.hextree.attacksurface",
                        "io.hextree.attacksurface.activities.Flag9Activity"
                ));
                startActivityForResult(intent, 42);
            }
        });
    }
```

---

# **Explicit vs. Implicit Intents**

Inside many `<activity>` tags you can often also find `<intent-filter>`. These intent filters serve an important role in the resolution of implicit intent.

If your app creates an implicit intent with a specific action, category or data URI, the Android system can look through the intent filters and find a matching app.

---

# **Hijack Implicit Intents**

As an attacker we rarely *send*  implicit intents, because usually we want to explicitly target a specific vulnerable app.

But *receiving* implicit intents could result in typical issues. If an app uses implicit intents insecurely, for example when it transmits sensitive data, then registering a handler for this intent could exploit this.

---

# Pending Intent

[Pending intents](https://developer.android.com/privacy-and-security/risks/pending-intent) are used in lots of places within Android. It allows one app to create a start activity intent and give it to another app to start the activity "in its name".

We have seen intent redirects before, and pending intents basically work exactly like that. Except that the "redirected" pending intent will run with the permission of the original app.

While this mitigates the typical intent redirect vulnerability, if we somehow get ahold of a pending intent from a victim app, it could lead to various issues.

---

# **Browser-to-App Attack Surface**

So far we looked at the app-to-app attack surface involving intents. But some activities can also be reached by a website in the browser. This is of course a much more interesting attack model, as it doesn't require a victim to install a malicious app. These web links that result into opening an app are so called [deep links](https://developer.android.com/training/app-links/deep-linking).

As shown in the video, exposing activities through a deep link could happen accidentally. Also some developers intended the exported activities just to be called by a link which is very limited, but these exposed activities can still be called by other apps as well.

---

# **Hijacking Deep Link Intents**

Deep links are not specifically target at an app, so they can be hijacked like any other implicit intent if the `<intent-filter>` are properly setup. The Intent Attack Surface app implements a typical "login via web" flow which you should hijack.

---

# **Generic Chrome intent: Scheme**

Chrome on Android implements a [custom scheme `intent:`](https://developer.chrome.com/docs/android/intents) with a lot more features than the regular deep links. Which make them very useful for an attacker.

`intent://` features:

1. It's a generic intent
2. Control the action and category
3. Target specific app and class
4. Add extra values

This chrome feature increases the threat surface massively of any app.

---

# **Android App Links**

We have seen how easy it is for a malicious app to hijack deep link intents. Thus they should not be used for any sensitive data such as login flows. The Chrome `intent://` scheme solves this by allowing a site to create explicit intents that cannot be intercepted. However there exists another solution.

So called [app links](https://developer.android.com/training/app-links) can be used to cryptographically verify that an app is allowed to handle certain links. This prevents the links from being hijackable by other apps.

**THANKS FOR READING ❤️**


