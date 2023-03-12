let loadTime;

const malloc = new NativeFunction(Module.findExportByName('libc.so', 'malloc'), 'pointer', ['int']);
const free = new NativeFunction(Module.findExportByName('libc.so', 'free'), 'void', ['pointer']);
const memset = new NativeFunction(Module.findExportByName('libc.so', 'memset'), 'pointer', ['pointer', 'int', 'int']);

function hook() {
    const evalStringPtrArr = {};
    const baseAddr = Module.findBaseAddress("libcocos2djs.so");
    Module.enumerateExportsSync("libcocos2djs.so").forEach(function (exp) {
        if (exp.name.indexOf("evalString") !== -1 &&
            exp.name.indexOf("Cocos2dxJavascriptJavaBridge") === -1) {
            evalStringPtrArr[exp.name] = exp.address;
        }
    });
    // console.log(JSON.stringify(evalStringPtrArr));
    if (Object.keys(evalStringPtrArr).length > 1) {
        send({status: "warn", msg: "Multiple feature functions found, please check manually."});
    }
    if (Object.keys(evalStringPtrArr).length === 0) {
        send({status: "warn", msg: "No feature functions found, please check manually."});
        setTimeout(hook, 100);
        return;
    }

    const evalStringPtr = evalStringPtrArr[Object.keys(evalStringPtrArr)[0]];

    const bufList = [];

    Interceptor.attach(evalStringPtr, {
        onEnter: function(args){

            const scriptSize = args[2].toInt32();
            const scripts = args[1].readCString();
            const fileName = args[4].readCString();

            send({status: "callback", callback: {scripts: scripts, size: scriptSize, filename: fileName}});

            loadTime = new Date().getTime();
            const op = recv('callback', function (value) {

                const length = value.payload.size === -1 ? value.payload.content.length : value.payload.size;
                const buf = malloc(length);
                bufList.push(buf);
                memset(buf, 0, length);
                buf.writeUtf8String(value.payload.content);

                args[1] = buf;
                args[2] = new NativePointer(value.payload.size);
                send({status: "done", callback: {scripts: scripts, size: scriptSize, filename: fileName}});
            });
            op.wait();
        },
        onLeave: function (retval) {
            const freePtr = bufList.pop();
            if (freePtr) {
                free(freePtr);
            }


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
