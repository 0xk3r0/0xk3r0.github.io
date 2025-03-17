---
layout: post
title: 'Understanding Dynamic Analysis by Solving HTB Supermarket Mobile Challenge'
date: 2025-03-16 21:51 +0200
categories: Mobile
tags: Android HackTheBox Mobile
---
Understanding Dynamic Application Security Testing (DAST) for mobile applications is essential to comprehend the communication between the app and other resources like shared object (`.so`) libraries. In this challenge, we will use the `Objection` tool, a powerful mobile tool for dynamic analysis, offering features like SSL Pinning, Root Detection Bypass, and more.

Let's start by installing the app on our emulator. I prefer using **LDplayer** and decompiling the APK using **JADX** to analyze the `AndroidMainFest.xml` file.

## Application Analysis

When I opened the application on the emulator, I discovered that it appears to be a market for buying items. There's a coupon field where you can apply a code for discounts: 
![](/Images/1.png)

**Here's what I found:**
- I tried entering random numbers in the coupon field, but nothing happened.
The account initially has only `$50`.
- I selected an item costing `$5` and bought it `10` times, which depleted the entire account balance.
- A popup message appears stating insufficient funds for further purchases: ![](/Images/2.png) 
- When clicking the buy button, another popup states that the order is shipped for delivery. 
![](/Images/3.png) 


## Static Analysis
Checking the `AndroidMainFest.xml` file, I found it contains only one activity, which is MainActivity:
![](/Images/4.png)


Exploring the code in MainActivity, I found an interesting function defining item prices. All items are set to a `$5` price, but the code invokes other **classe_methods** to validate the coupon code. If valid, it applies a `50%` discount, making each item cost `$2.5` instead of `$5`. This allows us to buy more items.
```java
        public void onTextChanged(CharSequence charSequence, int i2, int i3, int i4) {
            try {
                String obj = MainActivity.this.f2075q.getText().toString();
                MainActivity mainActivity = MainActivity.this;
                String stringFromJNI = mainActivity.stringFromJNI();
                Objects.requireNonNull(mainActivity);
                SecretKeySpec secretKeySpec = new SecretKeySpec(mainActivity.stringFromJNI2().getBytes(), mainActivity.stringFromJNI3());
                Cipher cipher = Cipher.getInstance(mainActivity.stringFromJNI3());
                cipher.init(2, secretKeySpec);
                int i5 = 0;
                if (!obj.equals(new String(cipher.doFinal(Base64.decode(stringFromJNI, 0)), "utf-8"))) {
                    MainActivity.this.f2081w.clear();
                    MainActivity.this.f2076r = 5.0d;
                    while (true) {
                        String[] strArr = this.f2085c;
                        if (i5 >= strArr.length) {
                            break;
                        }
                        MainActivity.this.f2081w.add(strArr[i5]);
                        i5++;
                    }
                } else {
                    MainActivity.this.f2081w.clear();
                    MainActivity.this.f2076r = 2.5d;
                    while (true) {
                        String[] strArr2 = this.f2084b;
                        if (i5 >= strArr2.length) {
                            break;
                        }
                        MainActivity.this.f2081w.add(strArr2[i5]);
                        i5++;
                    }
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
            MainActivity.this.s();
        }
```

The invoked **classe_methods** are **stringFromJNI**, **stringFromJNI2**, and **stringFromJNI3**.
![](/Images/5.png)

After checking the code, I noticed these **classe_methods** are invoked from a native library:
```java
static {
        System.loadLibrary("supermarket");
  }
```

## Native Library Analysis
I downloaded the library and opened it using **Ghidra**. Unfortunately, it was challenging to analyze the code for these methods, as you can see below:
```c
  local_1e0 = (void *)((int)&local_190 + 1);
  do {
    bVar2 = *pbVar5;
    bVar1 = **(byte **)((int)&uStack_28 + iVar8 * 4 + 4);
    if ((local_190 & 1) == 0) {
      uVar7 = local_190 >> 1 & 0x7f;
      uVar6 = 10;
    }
    else {
      uVar6 = (local_190 & 0xfffffffe) - 1;
      uVar7 = local_18c;
    }
    if (uVar7 == uVar6) {
                    /* try { // try from 000191ff to 00019217 has its CatchHandler @ 000192c2 */
      std::__ndk1::basic_string<>::__grow_by((basic_string<> *)&local_190,uVar6,1,uVar6,uVar6,0, 0);
      if ((local_190 & 1) != 0) goto LAB_0001921f;
LAB_00019234:
      local_190 = CONCAT31(local_190._1_3_,(char)uVar7 * '\x02' + '\x02');
      pvVar3 = (void *)((int)&local_190 + 1);
    }
    else {
      if ((local_190 & 1) == 0) goto LAB_00019234;
LAB_0001921f:
      local_18c = uVar7 + 1;
      pvVar3 = local_188;
    }
    *(byte *)((int)pvVar3 + uVar7) = bVar2 ^ bVar1;
    *(undefined *)((int)pvVar3 + uVar7 + 1) = 0;
    if (iVar8 == 0) {
      if ((local_190 & 1) != 0) {
        local_1e0 = local_188;
      }
                    /* try { // try from 0001927d to 00019289 has its CatchHandler @ 000192c0 */
      uVar4 = (**(code **)(*param_1 + 0x29c))(param_1,local_1e0);
      if ((local_190 & 1) != 0) {
        operator.delete(local_188);
      }
      if (*(int *)(in_GS_OFFSET + 0x14) == local_18) {
        return uVar4;
      }
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    pbVar5 = *(byte **)((int)&local_d0 + iVar8 * 4);
    iVar8 = iVar8 + 1;
  } while( true );
```

## Dynamic Analysis using Objection
Now, let's try to get the return value from this library through dynamic analysis using **Objection**. First, we need to run the Frida server and then run the Objection tool using:
```powershell
 objection.exe --gadget com.example.supermarket explore
```

### Listing Methods
We need to list class methods used by the app activity using:
```powershell
android hooking list class_methods com.example.supermarket.MainActivity
```

The following methods are found:
```powershell
public native java.lang.String com.example.supermarket.MainActivity.stringFromJNI()
public native java.lang.String com.example.supermarket.MainActivity.stringFromJNI2()
public native java.lang.String com.example.supermarket.MainActivity.stringFromJNI3()
public void com.example.supermarket.MainActivity.onCreate(android.os.Bundle)
public void com.example.supermarket.MainActivity.s()

Found 5 method(s)
```

### Hooking Methods
Let's hook the first method:
```powershell
com.example.supermarket on (Xiaomi: 9) [usb] # android hooking watch class_method com.example.supermarket.MainActivity.stringFromJNI --dump-args --dump-backtrace --dump-return
```
After entering a random value in the coupon field, it returned something like Ciphered text with base64 encode:
![](/Images/6.png)

Now, hook `stringFromJNI2`:
```powershell
com.example.supermarket on (Xiaomi: 9) [usb] # android hooking watch class_method com.example.supermarket.MainActivity.stringFromJNI2 --dump-args --dump-backtrace --dump-return
```
After entering also a random value in the coupon field, it returned something like key:
![](/Images/7.png)

### Lastly, hook stringFromJNI3:
```powershell
com.example.supermarket on (Xiaomi: 9) [usb] # android hooking watch class_method com.example.supermarket.MainActivity.stringFromJNI3 --dump-args --dump-backtrace --dump-return
```
Return value shows this uses the `AES` encryption algorithm:
![](/Images/8.png)



## Decryption
We now have the cipher, key, and algorithm (**AES**). The **AES** algorithm can have different modes like CBC, ECB, etc. Since we only have the cipher and key, it's reasonable to assume the mode is **ECB** since it doesn't require an Initialization Vector (IV).

I used the [CyberChef](https://cyberchef.org/) website to perform Base64 decoding followed by AES Decryption (ECB mode), and successfully obtained the flag:
![](/Images/9.png)

When this flag is submitted as a discount code, it applies a 50% discount on all items, 
reducing the price from `$5` to `$2.5`:

![](/Images/last.png)

**THANKS FOR READING ❤️**
