---
layout: post
title: 'HackTheBox: Supermarket Mobile Challenge'
date: 2025-03-16 21:51 +0200
categories: Mobile
tags: Android HackTheBox Mobile
---

Understanding Dynamic Application Security Test (DAST) for mobile application is very useful to understand the communication between the app and the other resources like shared object (.so) library, so we will solve this challenge using `Objectio` tool, this is the powerful mobile tool use for dynamic analysis and this too offer many things useful like SSL Pinnning, Root Ditication bypass .. and more.

Let's Start now by installing the app on our emulator i preffer to use `LDplayer` also decompile the apk using `JADX` to analyse `AndroidMainFest.xml` file.

When i explore the application when i opened it on the emulator i found it apears to be a market for buying items and thie's a coupon you can apply for more offer on the prices: 
![]() 

I tried to add any random numbers to the coupon field but thier wasnt thing happen. As you can see we have only 50$ in our account, then i select item it cost 5$ and i buy it 10 times, now we lost our all money i noticed there is popup tell us we dont have enough money to buy any thing more. Then by click `buy` button it popup that the order shaped to delivry:
![]()

Now let's move into static analysis, for the mainfest file i found it only contain one activity which it MainActivity:
![]()

So double click on it to explore it code, i found this is the implementation code for the screen that we saw above, then while reading the code i found interestid function that declare the price of items, and it set all items to be 5$ price and also this invoke other classes to check our copoun code and if it valid it apply 50% offer on the all items, so each item will be 2.5$ rather than 5$ and we can buy more than we buyed.
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
These invoked classes are stringFromNI, stringFromJNI2, stringFromJNI3.
I tried to get the implementation code for these classes but i didn't find it, but i saw these calss methods invoked from native library:
![]()

I found also in the code it load system library called `supermarket`:
```java
static {
        System.loadLibrary("supermarket");
  }
```
After that i go to the path of this library downloaded it and open it using ghidra tool, unfortianatlly i found it was diffecult to anaylsis the code for this class methods as u see:
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

Let's try to get the requests and responses between app and this library through dynamic analysis using `Objection`, first we need to run frida server then run the objection too using this command:
```powershell
 objection.exe --gadget com.example.supermarket explore
```
![]()

then for hooking the application to watch the methods we need first to list class methods that app activity use using this command:
```powershell
android hooking list class_methods com.example.supermarket.MainActivity
```

There's 5 methods founded: 
```powershell
public native java.lang.String com.example.supermarket.MainActivity.stringFromJNI()
public native java.lang.String com.example.supermarket.MainActivity.stringFromJNI2()
public native java.lang.String com.example.supermarket.MainActivity.stringFromJNI3()
public void com.example.supermarket.MainActivity.onCreate(android.os.Bundle)
public void com.example.supermarket.MainActivity.s()

Found 5 method(s)
```
Let's hook first method using this command: 
```powershell
com.example.supermarket on (Xiaomi: 9) [usb] # android hooking watch class_method com.example.supermarket.MainActivity.stringFromJNI --dump-args --dump-backtrace --dump-return
```
after a watch the hooking for this method i try enter the copoun code.
