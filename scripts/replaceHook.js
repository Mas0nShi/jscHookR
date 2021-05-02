var loadTime;
function hook() {
    Java.perform(function(){

        var evalStringPtrArr = {};
        var exports = Module.enumerateExportsSync("libcocos2djs.so");
        for(var i = 0; i < exports.length; i++) {
            if(exports[i].name.indexOf('evalString') != -1 && exports[i].name.indexOf("Cocos2dxJavascriptJavaBridge") == -1){
                evalStringPtrArr[exports[i].name] = exports[i].address;
                var evalString = exports[i].address;
                // break;
            }
        }
        if (evalStringPtrArr.length > 1) {
            send({Status:"Warning",  Msg: "Hook Ptr is not unique."})
        }
        //var evalString = Module.findExportByName("libcocos2djs.so", "_ZN2se12ScriptEngine10evalStringEPKciPNS_5ValueES2_")
        if(evalString == null) {
            // console.log("None evalString ptr");
            setTimeout(hook, 100);
            return;
        }
        Interceptor.attach(evalString, {
            onEnter: function(args){
                // var codeData = args[1].readCString();
                // var codeSize = args[2];
                var pathName = args[4].readCString();

                loadTime = new Date().getTime();
                send({Status:"Wait", Path: pathName});

                var op = recv('input', function(value) {
                    if(value.payload["Status"] === "Replace"){
                        //console.log(parseInt(value.payload["Size"], 16),args[2].toInt32(), args[2], args[1].readCString().length)

                        if (parseInt(value.payload["Size"], 16) > args[1].readCString().length) {

                            send({Status:"Warning", Msg: "File: " + pathName + " size may exceeds the source file, which may cause the App to run abnormally, please reduce the file size."});
                        }

                        args[1].writeUtf8String(value.payload["Data"]);
                        send({Status:"replaceOk", Path: pathName});
                    }
                });
                op.wait();
            }
        })
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
