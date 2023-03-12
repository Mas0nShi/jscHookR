# jscHookR

## TL;DR

a reverse engineering tool for android cocos2d-js engine application.

support dump and replace .jsc files.

## Usage

Note: use android-frida-server at least `16.0.0+`

1. Install

    ``` bash
    git clone https://github.com/Mas0nShi/jscHookR
    pip3 install -r requirement.txt
    cd jscHookR
    ```
   
2. Enjoy it

    e.g.
    
    ```bash
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
