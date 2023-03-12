let loadTime;

function hook() {
    const evalStringPtrArr = {};
    Module.enumerateExportsSync("libcocos2djs.so").forEach(function (exp) {
        // skip JavaBridge functions.
        if (exp.name.indexOf("evalString") !== -1 &&
            exp.name.indexOf("Cocos2dxJavascriptJavaBridge") === -1) {
            evalStringPtrArr[exp.name] = exp.address;
        }
    });

    // get the unique feature function.
    if (Object.keys(evalStringPtrArr).length > 1) {
        send({status: "warn", msg: "Multiple feature functions found, please check manually."});
    }

    // retry if no feature function found.
    if (Object.keys(evalStringPtrArr).length === 0) {
        send({status: "warn", msg: "No feature functions found, please check manually."});
        setTimeout(hook, 100);
        return;
    }

    const evalStringPtr = evalStringPtrArr[Object.keys(evalStringPtrArr)[0]];
    send({status: "log", msg: "Hooking " + Object.keys(evalStringPtrArr)[0] + " at " + evalStringPtr});

    /**
     *  __int64 __fastcall se::ScriptEngine::evalString(
     *         se::ScriptEngine *this,
     *         const char *scripts,
     *         unsigned __int64 len,
     *         se::Value *a4,
     *         const char *filename)
     * */
    Interceptor.attach(evalStringPtr, {
        onEnter: function(args){
            const scriptSize = args[2].toInt32();
            const scripts = args[1].readUtf8String();
            const fileName = args[4].readCString();

            send({status: "callback", callback: {scripts: scripts, size: scriptSize, filename: fileName}});
            loadTime = new Date().getTime(); // refresh the load time.
        }
    })
}


function delay(isEnd=false, time){
    if (new Date().getTime() - loadTime > time * 1000) {
        send({status:"stop", msg: "detect the cocos2d-js script lazy loaded, auto stop the script."});
    } else if (!isEnd){
        setTimeout(delay, time * 1000, isEnd, time);
    }
}

// start the script.
