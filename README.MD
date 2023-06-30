# jscHookR

## TL;DR

a reverse engineering tool for android cocos2d-js engine application.

support dump and replace .jsc files.

## Usage

Note: use android-frida-server at least `16.0.0+`

1. 🔧 Install

    ``` shell
    git clone https://github.com/Mas0nShi/jscHookR
    pip3 install -r requirements.txt
    cd jscHookR
    ```

   ⚠️ Tips: You can edit [requirements.txt](requirements.txt) to avoid environment pollution. (frida & frida-tools)

2. 📱 Start frida-server

   use your debuggable android device or emulator, download suitable frida-server, push to device and run it.

   e.g.

   ```shell
    adb push frida-server-16.0.0-android-arm64 /data/local/tmp/frida-server
    adb shell chmod +x /data/local/tmp/frida-server
    adb shell /data/local/tmp/frida-server &
    ```

3. ☕️ Enjoy it 

    e.g.
    
    ```shell
    # Dump .jsc files
    python3 frida-jsc-hook.py -p com.mas0n.testApp -d -o . 
    # Replace .jsc files
    python3 frida-jsc-hook.py -p com.mas0n.testApp -r -i ./com.mas0n.testApp
    ```

## Features

- [x] dump scripts loaded by cocos2d-js engine.
- [x] runtime replace (include no-filename scripts)

## Preview

![preview](screenshot/preview.png)
