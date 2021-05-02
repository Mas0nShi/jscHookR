# jscHookR



# luac-Decryption
⛔Not applicable to binary files compiled with SpiderMonkey⛔

⚡This is a tool for reverse engineering cocos2djs Apps.⚡

👀 require: `frida`


### Usage :
        python main.py [-d] [PackageName]
        python main.py [-r] [PackageName]
### Example :
        python main.py -d com.mas0n.testApp
        python main.py -r com.mas0n.testApp
### Tips :
        -d [-dump] 
        -r [-replace] (DirPath/PackageName)
        If you want to specify a folder replacement, You can add optional parameters: [absDir]
        Support: dump .jsc files/local overrides
### Outputs :
        The exported file is in the current running directory.

### ❗Notice :
    The replacement file cannot be larger than the source file, otherwise an unknown error will occur.


 **Welcome to submit issue.**

![example](https://github.com/Mas0nShi/jscHookR/blob/master/example.png)

If you have any questions, please contact [ MasonShi@88.com ]
