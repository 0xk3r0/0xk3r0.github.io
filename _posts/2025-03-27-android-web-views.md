---
layout: post
title: 'Android Web-Views'
date: 2025-03-27 16:15 +0200
---
# **WebViews vs. CustomTabs**

Many apps are not written in Java or Kotlin, but get implemented in Javascript and HTML that then gets rendered in a [WebViews](https://developer.android.com/develop/ui/views/layout/webapps/webview). So when looking for security issues in apps, WebViews are a very important attack surface. In very old Android versions (2013), WebViews were very insecure and could even [lead to arbitrary code execution](https://labs.withsecure.com/publications/webview-addjavascriptinterface-remote-code-execution). However in modern Android, this is not possible anymore.

Besides WebViews, there also exists so called [Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs). This is a more modern feature that is rarely covered in Android app security courses. That's why we will also explore them in this course.

---

# **What is a WebView?**

Let's have a look at [WebView](https://developer.android.com/reference/android/webkit/WebView) from the perspective of a developer by playing around with it in an example app.

A WebView is an actual UI component that can be added into the layout .xml of the app.

```xml
<WebView
    android:id="@+id/big_webview"
    android:layout_width="match_parent"
    android:layout_height="match_parent">
</WebView>
```

The WebView element can then be referenced in the application code to load a URL in it.

```java
WebView webView = findViewById(R.id.big_webview);
webView.loadUrl("https://www.hextree.io");
```

As an attacker we want to think about what happens if an attacker could control the URL loaded in a WebView, or what can be done if we find a web vulnerability like Cross-site scripting.

---

# **Access Local Files**

While WebView often serves content from the internet, it can also load local HTML and JavaScript files from within the app itself. This is useful for offline functionality or even when the app is entirely implemented in HTML and Javascript.

Android applications can include an `/assets/` folder in their project structure. This folder is bundled into the final APK and is accessible at runtime. And WebView has a built in feature to load these files via `file:///android_asset/` (or `file:///android_res/`):

```java
WebView webView = findViewById(R.id.webView);
webView.getSettings().setJavaScriptEnabled(true); // Enable JavaScript if needed
webView.loadUrl("file:///android_asset/index.html");

```

Note that `file:///android_asset/` is considered outdated and Android officially [recommends to use an AssetLoader](https://developer.android.com/develop/ui/views/layout/webapps/load-local-content) instead.

Because asset files are bundled in the APK publicly distributed in the Play Store, they are considered public. That's why WebViews can load them even when file access is generally not enabled. To be able to load other app internal files, the WebView [WebSettings](https://developer.android.com/reference/android/webkit/WebSettings) have to be changed:

```java
WebView webView = findViewById(R.id.webView);
webView.getSettings().setAllowFileAccess(true);
//webView.getSettings().setAllowContentAccess(true);
//webView.getSettings().setAllowFileAccessFromFileURLs(true);
//webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
```

Some settings like [`setAllowUniversalAccessFromFileURLs`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowUniversalAccessFromFileURLs(boolean)) are very dangerous, but might still be required by some apps. We will look deeper into those settings as well.

---

# **@JavaScriptInterface**

WebViews in Android can allow JavaScript running in the WebView to [call native Java methods](https://developer.android.com/develop/ui/views/layout/webapps/webview#BindingJavaScript). This is especially useful if the app logic is primarily implemented in HTML/Javascript and wants to access native Android features.

If an attacker can control the document loaded into a WebView, these exposed Java methods could lead to security issues.

To expose native functionality to the WebView, the developer has to create a class with methods annotated with [`@JavascriptInterface`](https://developer.android.com/reference/android/webkit/JavascriptInterface).

```java
class MyNativeBridge {
    @JavascriptInterface
    public void init(String msg) {
        // [...]
    }
    @JavascriptInterface
    public String getData() {
        // [...]
        return db.getData();
    }
}

```

This object can then be exposed to the WebView by calling [`addJavascriptInterface()`](https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String))

```java
WebView webView = findViewById(R.id.main_webview);
webView.addJavascriptInterface(new MyNativeBridge(), "app");
webView.loadUrl(url);

```

On the side of the website, this object will become available on the global `Window` object with the name given in the call to `addJavascriptInterface(object, name)`.

```html
<script>
window.app.init("Hello");
</script>

```

Does `addJavascriptInterface()` lead to arbitrary code execution in the WebView?

Back in Android 4, it was possible to use the JavascriptInterface to access any other Java object and call arbitrary methods. Leading to arbitrary code execution.

But in modern WebView this does not work anymore. Only methods annotated with `@JavascriptInterface` can be accessed.

Have a look at the `@JavascriptInterface` challenge from the Intent Attack Surface app. If you struggle to implement the exploit via your own website, simply move on.

---

# **WebView Exploit Development**

It can be a hassle to create malicious websites when attacking WebViews. So let's go over different techniques how we can solve the `@JavasriptInterface` challenge from the Intent Attack Surface app.

## **Hextree VSCode Lab**

The [VSCode Lab](https://app.hextree.io/lab/vscode) is a Hextree subscription feature that opens a VSCode IDE in the browser and it also runs `nginx` exposed on another subdomain.

By using the IDE we can modify the HTML content in `/var/www/html/` and get a HTTPS URL to be used in the attack of the WebView.

## **Setup Own Server**

You can also rent a server on eg. Hetzner or Digital Ocean and then follow [any tutorial](https://www.digitalocean.com/community/tutorials/how-to-install-nginx-on-ubuntu-20-04) to setup a server like `nginx` yourself.

Besides a full heavy webserver you can also run some lightweight development server like `php -S 0.0.0.0:80` or `python3 -m http.server 80`.

Alternatively you can also use a service like [ngrok](https://ngrok.com/) to run a server locally, and expose it over the internet.

## **Data URI:**

Sometimes it can be enough to just create a data URI

`data:text/html,<script>alert(1)</script>`

## **Hextree WebView Pwn**

We have created a page that runs various tests to analyse the current render context. It also offers a JS shell so you can easily explore the page and execute the attack from within the 
[WebView](https://oak.hackstree.io/android/webview/pwn.html).

---

# **Cross-Site Scripting in WebViews**

It's not always necessary to be able to control the URL passed to `webview.loadUrl(url)`. Because the WebView renders websites, the entire field of web security is also relevant. Especially Cross-site Scripting (XSS) issues are very useful to attack WebViews.

Cross-Site Scripting (XSS) is a very unintuitive vulnerability name. Instead think of *"HTML Injection"* or *"Javascript Injection"*

Classic XSS issues are introduced either by the web server or the Javascript app itself. For example by not properly doing output encoding or passing attacker controlled data to dangerous functions like `window.location=[...]`.

But XSS in WebViews could also happen through other means, for example by injecting code into a call to [`webview.evaluateJavascript()`](https://developer.android.com/reference/android/webkit/WebView#evaluateJavascript(java.lang.String,%20android.webkit.ValueCallback%3Cjava.lang.String%3E)).

---

# **Same Origin Policy Settings**

The Same-Origin Policy (SOP) is important for websites and browsers, to ensure one website cannot access another website. Does this also apply to WebViews? If yes, in what way?

To play around with different WebView settings and how this influences SOP, we have created a test app. You can find the source code [here](https://github.com/hextreeio/android-webview-research/)

**Download File**

[io.hextree.webview_debug.apk](https://storage.googleapis.com/hextree_prod_image_uploads/media/uploads/intent-threat-surface/io.hextree.webview_debug.apk)

# **Same Origin Policy (SOP)**

SOP ensures that JavaScript can only access resources from the same origin (defined by the protocol, hostname, and port).

For example JavaScript executed on [https://example.com](https://example.com/)

- can access other resources like **https://example.com/secret.xml**.
- cannot access **https://another.com/secret.xml**

# **WebView Settings**

Depending on the [WebView settings](https://developer.android.com/reference/android/webkit/WebSettings) and the origin of the loaded `.html` document, the test case results vary. Using the app you can change the settings on the fly to observe their impact:

- [`setJavaScriptEnabled(boolean)`](https://developer.android.com/reference/android/webkit/WebSettings#setJavaScriptEnabled(boolean))
- [`setAllowContentAccess(boolean)`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowContentAccess(boolean))
- [`setAllowFileAccess(boolean)`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccess(boolean))
- [`setAllowFileAccessFromFileURLs(boolean)`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccessFromFileURLs(boolean))
- [`setAllowUniversalAccessFromFileURLs(boolean)`](https://developer.android.com/reference/android/webkit/WebSettings#setAllowUniversalAccessFromFileURLs(boolean))

---

# **Stealing App-Internal Files**

When WebViews have settings like `AllowFileAccessFromFileURLs` or `AllowUniversalAccessFromFileURLs` enabled, the impact of a compromised WebView increases a lot. In that case an attacker could steal app-internal files like the shared preferences.

## **Leak via XMLHttpRequest**

Example code snippet that tries to read the content of a URL using XHR.

```jsx
function leakFileXHR(url) {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.responseText) {
            console.log(xhr.responseText);
        }
    };
    xhr.onerror = function(error) {
        // console.log(error);
    }
    xhr.send();
}
```

## **Leak via <iframe>**

The following functions creates an `<iframe>` of a given URL and attempts to read the document's content.

```jsx
function leakFileIframe(url) {
  const iframe = document.createElement('iframe');
  iframe.onload = () => {
    const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
    if (!iframeDoc) return;
    const contentType = iframeDoc.contentType;
    const data = iframeDoc.documentElement.innerHTML;
    const blob = new Blob([data], { type: contentType });
    const reader = new FileReader();
    const contentPromise = new Promise((resolve, reject) => {
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsText(blob);
    });
    contentPromise.then(content => {
      if (content && !content.includes("net::ERR_")) {
        console.log(content);
      }
    });
  };
  document.body.appendChild(iframe);
  iframe.src = url;
}
```

---

# **WebView Intent Handling**

WebView does not natively support intent:// URIs (used in Chrome to send intents from websites). However, developers may implement [custom logic](https://stackoverflow.com/questions/33151246/how-to-handle-intent-on-a-webview-url) to handle these intents, making the app vulnerable if not properly secured.

Example custom code to handle `intent://` URIs:

```java
// https://stackoverflow.com/questions/33151246/how-to-handle-intent-on-a-webview-url
@Override
public boolean shouldOverrideUrlLoading(WebView view, String url) {
    if (url.startsWith("intent://")) {
        try {
            Context context = view.getContext();
            Intent intent = Intent.parseUri(url, Intent.URI_INTENT_SCHEME);
            if (intent != null) {
                view.stopLoading();
                PackageManager packageManager = context.getPackageManager();
                ResolveInfo info = packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY);
                if (info != null) {
                    context.startActivity(intent);
                } else {
                    String fallbackUrl = intent.getStringExtra("browser_fallback_url");
                    view.loadUrl(fallbackUrl);
                    // or call external broswer
                    // Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(fallbackUrl));
                    //context.startActivity(browserIntent);
                }
                return true;
            }
        } catch (URISyntaxException e) {
            if (GeneralData.DEBUG) {
                Log.e(TAG, "Can't resolve intent://", e);
            }
        }
    }
    return false;
}
```

---

# **What are CustomTabs?**

[Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs) are a different way to display web content within an app. Unlike WebViews, Custom Tabs are actually not a UI element. Instead, they rely on the browser installed on the device to provide the interface and functionality.

Read more about it [here](https://web.dev/articles/web-on-android#custom_tabs_as_a_solution_for_in-app_browsers)

```java
// Launcha a basic CustomTab
CustomTabsIntent customTabsIntent = new CustomTabsIntent.Builder()
    .setToolbarColor(ContextCompat.getColor(this, R.color.colorPrimary))
    .addDefaultShareMenuItem()
    .build();

customTabsIntent.launchUrl(this, Uri.parse("https://hextree.io"));

```

The code above actually sends an intent to the default Browser and the browser then displays the website. Does that mean CustomTabs don't introduce any security issues in our app?

---

# **CustomTabs vs. WebView Attack Surface**

Generally CustomTabs are "safer", but some apps require the features of WebViews. So what exactly are the differences?

- **WebView** is an actual embedded browser within your app. It is isolated from other apps, meaning a user logged into a website in their primary browser will not be logged in via the WebView.
- **Custom Tabs** simply interacts with the default browser on the device (e.g., Chrome). It shares session data, cookies, and accounts with the browser, meaning users are already logged into websites they’ve accessed in the browser.

> “Custom Tabs is effectively a tab rendered by the user's browser”
> 

In terms of security, Custom Tabs do not have access to your app internal files or FileProviders and cannot change the Same Origin Policy behaviour.

Due to these benefits, Google generally recommends developers to use Custom [Tabs](https://support.google.com/faqs/answer/12284343?hl=en-GB)

See also:
- [web-on-android](https://web.dev/articles/web-on-android)
- [custom-tabs-faq](https://chromium.googlesource.com/chromium/src/+/refs/tags/122.0.6253.7/docs/security/custom-tabs-faq.md)

While apps cannot expose native Java methods in Custom Tabs, apps can still setup a postMessage() communication which could be exploited in similar ways. More about that next.

---

# **Digital Asset Links Verified Origins**

Websites can declare their association with an Android app, by [creating a Digital Asset Links](https://developers.google.com/digital-asset-links/v1/getting-started).

For example [`.well-known/assetlinks.json`](https://google.com/.well-known/assetlinks.json) from Google shows that the app `com.google.android.googlequicksearchbox` is allowed to use [google.com](https://google.com/) as its origin.

```json
{
  "relation": ["delegate_permission/common.handle_all_urls", "delegate_permission/common.use_as_origin"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.google.android.googlequicksearchbox",
    "sha256_cert_fingerprints": [
      "F0:FD:6C:5B:41:0F:25:CB:25:C3:B5:33:46:C8:97:2F:AE:30:F8:EE:74:11:DF:91:04:80:AD:6B:2D:60:DB:83",
      "19:75:B2:F1:71:77:BC:89:A5:DF:F3:1F:9E:64:A6:CA:E2:81:A5:3D:C1:D1:D5:9B:1D:14:7F:E1:C8:2A:FA:00"
    ]
  }
}
```

When using Custom Tabs, a browser like Chrome can validate that the app is associated with a website by visiting the `assetlinks.json` file and validate the package name and signature.

If the validation succeeds, the app gets a few more capabilities:

- More control over the Custom Tabs UI
- Adding arbitrary HTTP headers on the same origin
- Send and receive postMessage()

---

# **Post Message Communication**

[`postMessage()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) is a web feature to facilitate safe cross-origin communication.

Custom Tabs provide an Android implementation of the postMessage mechanism, enabling secure communication between an app and a website loaded in a Custom Tab. However, if not properly configured, this feature can lead to security vulnerabilities.

## **CustomTabs postMessage()**

In order to use `postMessage()`, the app has to first validate its origin and then request a postMessage channel:

```java
customTabsSession.requestPostMessageChannel(Uri.parse("https://oak.hackstree.io"));
```

The app can then override methods from the [`CustomTabsCallback`](https://developer.android.com/reference/androidx/browser/customtabs/CustomTabsCallback) to send and receive messages:

```java
@Override
public void onMessageChannelReady(@NonNull Bundle extras) {
    if (session != null) {
        session.postMessage("init", null);
    }
}

@Override
public void onPostMessage(@NonNull String message, @NonNull Bundle extras) {
    if (session == null) return;
    try {
        JSONObject jsonObject = new JSONObject(message);
        String msg_type = jsonObject.getString("message");
        switch(msg_type) {
            case "init": {
                // some code [...]
                break;
            }
            // [...]
        }
    } catch (JSONException e) {
        Log.e(TAG, "Error parsing JSON postMessage: " + e.getMessage());
    }
}
```

solving this challenge by modify postMessage while inspecting communication through browser console: 

```jsx
window.port.postMessage(JSON.stringify({message:"success"}));
```

---

# **Trusted Web Activites (TWA)**

[Trusted Web Activities](https://developer.android.com/develop/ui/views/layout/webapps/trusted-web-activities) provide another way to integrate web content into an Android app. This can be confusing at first, but turns out that TWAs also just rely on Custom Tabs at their core - they abstract much of the complexity, allowing developers to create apps that are essentially wrappers around websites with minimal effort.

One interesting detail is that the default TWA [`LauncherActivity`](https://github.com/GoogleChrome/android-browser-helper/blob/f4bdd7d4bfe2abf939bd9f4d881ff09ca5a33fe3/androidbrowserhelper/src/main/java/com/google/androidbrowserhelper/trusted/LauncherActivity.java#L350) gets the URL from the incoming intent. Which means most TWA apps can be forced to open an arbitrary URL:

```java
// targeting example app: https://github.com/revoltchat/android
Intent intet = new Intent();
intent.setClassName("chat.revolt.app.twa", "chat.revolt.app.twa.LauncherActivity");
intent.setData(Uri.parse("https://oak.hackstree.io/android/webview/pwn.html"));
startActivity();

```

However keep in mind that by itself this is not a security issue. Custom Tabs simply open the URL in the default browser, that is not much different from sending a VIEW intent to the browser directly. But if the app were to implement any additional custom features, that could become an issue.

**THANKS FOR READING ❤️**



