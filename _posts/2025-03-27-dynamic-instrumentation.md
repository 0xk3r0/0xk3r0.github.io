---
layout: post
title: Dynamic Instrumentation
date: 2025-03-27 02:04 +0200
categories: Hextree-Android-Course
tags: android hextree
---
1- To inject Frida into an APK we can use objection:

```powershell
objection patchapk -s apk_name.apk
```

Objection will extract, patch, re-pack, align and sign the application, and so it's a very fast and easy way to get Frida running.

Note that the application will wait on launch for Frida to connect to it, so to start the application we have to run:

```powershell
frida -U FridaTarget
```

The `-U` here specifies that we want to connect by USB.

2- If you have a rooted device, you can also run frida-server instead of patching the APK. You can download frida-server on the [Github Releases Page of Frida](https://github.com/frida/frida/releases). Note that it comes xz compressed, so you have to extract it (`xz -d` on unixoid systems, 7zip on for example Windows).

To install it in an emulator we can `adb push` the server over:

```powershell
adb push frida-server /data/local/tmp/
```

We chose this path because other parts, such as `/sdcard`, are commonly mounted no-exec.

Afterwards we want to run adb as root, and also make the server executable:
1. adb root
2. adb shell
3. cd /data/local/tmp
4. chmod +x frida-server

And then we are ready to go: We can launch the server by running

```bash
./frida-server
```

Now we can connect to the application by running:

```powershell
frida -U FridaTarget
```

3- The Frida REPL (Read-Eval-Print-Loop) is a JavaScript interpreter, and so we can directly run JavaScript statements:

```bash
for(var i=0; i < 5; i++) { console.log(i); }
```

To create multi-line statements, suffix each line with a `\` backslash:

```bash
for(var i=0; i < 5; i++) {\
    console.log(i);\
}
```

Check-out the full Frida JavaScript API documentation [here](https://frida.re/docs/examples/javascript/)!

To load scripts with Frida, we can just start Frida with the `-l` option:

```powershell
frida -U -l test.js FridaTarget
```

We can enable and disable auto-reload by doing:

```bash
%autoreload on/off
```

To manually reload all scripts, we can just run `%reload` in the REPL.

4- We can get JavaScript wrappers for Java classes by using `Java.use`:

```jsx
Java.use("java.lang.String")
```

We can then instantiate those classes by calling $new:

```jsx
var string_class = Java.use("java.lang.String");
var string_instance = string_class.$new("Teststring");
string_instance.charAt(0);
```

We can dispose of instances (for example to free up memory) using `$dispose()`, however this is almost never required, as the Garbage Collector should collect unused instances.

We can also replace the implementation of a method by overwriting it on the class:

```jsx
string_class.charAt.implementation = (c) => {
    console.log("charAt overridden!");
    return "X";
}
```

5- Example to call function that return decrypted flag:

```jsx
Java.perform(() => {
    let ExampleClass = Java.use("io.hextree.fridatarget.FlagClass");
    let ExampleInstance = ExampleClass.$new();
    console.log(ExampleInstance.flagFromStaticMethod());
    console.log(ExampleInstance.flagIfYouCallMeWithSesame("sesame"));// this function take pass paramter
})
```

---

### **Tracing Activities**

```jsx
Java.perform(() => {
    let ActivityClass = Java.use("android.app.Activity");
    ActivityClass.onResume.implementation = function() {
        console.log("Activity resumed:", this.getClass().getName());
        // Call original onResume method
        this.onResume();
    }
})
```

Trace By fragments:

```jsx
Java.perform(() => {
    let FragmentClass = Java.use("androidx.fragment.app.Fragment");
    FragmentClass.onResume.implementation = function() {
        console.log("Fragment resumed:", this.getClass().getName());
        // Call original onResume method
        this.onResume();
    }
})
```

### **Frida-trace**

Frida trace allows us to directly trace function calls.

To trace specific Method on `io.hextree.*`, we can do:

```jsx
frida-trace -U -j 'io.hextree.<ClassName>!<MethodName> <apkName>
```

To trace all calls on `io.hextree.*`, we can do:

```jsx
frida-trace -U -j 'io.hextree.*!*' <apkName>
```

To exclude Class on `io.hextree.*`, we can do:

```jsx
frida-trace -U -j 'io.hextree.*!*' -J <anoyingClass> <apkName>
```

We can also trace into native objects, by specifing the `-I` option:

```jsx
frida-trace -U -I 'libhextree.so' -j 'io.hextree.*!*' FridaTarget
```

We can also trace into native objects, by specifing the `-I` option:

```jsx
frida-trace -U -I 'libhextree.so' -j 'io.hextree.*!*' FridaTarget
```

---

### **Frida Interception Basics**

We can use Frida to intercept function calls and return values. For example, to replace the return value of InterceptionFragment.function_to_intercept, we can just write a simple script:

```jsx
Java.perform(() => {
    var InterceptionFragment = Java.use("io.hextree.fridatarget.ui.InterceptionFragment");
    InterceptionFragment.function_to_intercept.implementation = function(argument) {
        this.function_to_intercept(argument);
        return "SOMETHING DIFFERENT";
    }
})
```

To get method name : 

```jsx
Java.enumerateMethods("*okhttp*Builder!*")
Java.enumerateMethods("*Platform!*checkServerTrusted*")
```

And the above Classes  you can get it through `frida-trace:`

```jsx
frida-trace.exe -U -j "*!*okhttp3*" FridaTarget
frida-trace.exe -U -j "*!*checkServerTrusted*" FridaTarget
```

Then to bypass **SSL pining** and **network config**:

```jsx
Java.perform (() => {

    var ssl_bypass = Java.use("com.android.org.conscrypt.Platform");
    ssl_bypass.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.ConscryptEngine').implementation = function(){
        console.log("Check Server Trusted");
    }
})
```

For OKHTTP3-based pinning we need to combine the script of the previous video, and a small new one that prevents the SSLPinner from being added to the OkHttpClient:

```jsx
Java.perform(() => {
    var BuilderClass = Java.use("okhttp3.OkHttpClient$Builder");
    BuilderClass.certificatePinner.implementation = function() {
        console.log("Certificate pinner called");
        return this;
    }
})
```

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
