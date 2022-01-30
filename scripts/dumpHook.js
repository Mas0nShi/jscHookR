var loadTime;
function hook() {
        var evalStringPtrArr = {};
        var exports = Module.enumerateExportsSync("libcocos2djs.so");
        for(var i = 0; i < exports.length; i++) {
            if(exports[i].name.indexOf('evalString') != -1 && exports[i].name.indexOf("Cocos2dxJavascriptJavaBridge") == -1){
                evalStringPtrArr[exports[i].name] = exports[i].address;
                var evalString = exports[i].address;
            }
        }
        if (evalStringPtrArr.length > 1) {
            send({Status:"Warning"})
        }
        if(evalString == null) {
            setTimeout(hook, 100);
            return;
        }
        Interceptor.attach(evalString, {
            onEnter: function(args){
                var codeData = args[1].readCString();
                var codeSize = args[2];
                var pathName = args[4].readCString();
                send({Status:"hookOn", Data:codeData, Size:codeSize, Path:pathName});
                loadTime = new Date().getTime();
            }
        })
    }


function delay(isEnd){
    if (new Date().getTime() - loadTime > 5000) {
        send({Status:"END"});
    } else if (!isEnd){
        setTimeout(delay, 5000, isEnd);
    }
}

setImmediate(function(){
    setTimeout(hook, 10);
    delay();
})
