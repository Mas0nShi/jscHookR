# -*- coding: utf-8 -*-
# @Time    : 2021-04-28 17:03
# @Author  : Mas0n
# @FileName: main.py
# @Software: PyCharm
# @Blog    ：https://blog.shi1011.cn


import frida
import sys
import os
import random
import time
from traveDir import depthIteratePath
from loguru import logger

"""1.Print Log"""
try:
    from shutil import get_terminal_size as get_terminal_size
except:
    try:
        from backports.shutil_get_terminal_size import get_terminal_size as get_terminal_size
    except:
        pass
try:
    import click

except:
    class click:

        @staticmethod
        def secho(message=None, **kwargs):
            print(message)

        @staticmethod
        def style(**kwargs):
            raise Exception("unsupported style")

banner = """
 ooo        ooooo                      .oooo.              
 `88.       .888'                     d8P'`Y8b             
  888b     d'888   .oooo.    .oooo.o 888    888 ooo. .oo.  
  8 Y88. .P  888  `P  )88b  d88(  "8 888    888 `888P"Y88b 
  8  `888'   888   .oP"888  `"Y88b.  888    888  888   888 
  8    Y     888  d8(  888  o.  )88b `88b  d88'  888   888 
  o8o        o888o `Y888""8o 8""888P'  `Y8bd8P'  o888o o888o 

                     Running Start                           
\n"""


def show_banner():
    colors = ['bright_red', 'bright_green', 'bright_blue', 'cyan', 'magenta']
    try:
        click.style('color test', fg='bright_red')
    except:
        colors = ['red', 'green', 'blue', 'cyan', 'magenta']
    try:
        columns = get_terminal_size().columns
        if columns >= len(banner.splitlines()[1]):
            for line in banner.splitlines():
                if line:
                    fill = int((columns - len(line)) / 2)
                    line = line[0] * fill + line
                    line += line[-1] * fill
                click.secho(line, fg=random.choice(colors))
    except:
        pass


class ColorPrinter:
    @staticmethod
    def print_red_text(content, end="\n"):
        print("\033[1;31m %s \033[0m" % content, end=end),

    @staticmethod
    def print_green_text(content, end="\n"):
        print("\033[1;32m %s \033[0m" % content, end=end),

    @staticmethod
    def print_blue_text(content, end="\n"):
        print("\033[1;34m %s \033[0m" % content, end=end),

    @staticmethod
    def print_cyan_text(content, end="\n"):
        print("\033[1;36m %s \033[0m" % content, end=end),

    @staticmethod
    def print_white_text(content, end="\n"):
        print("\033[1;37m %s \033[0m" % content, end=end),


def readHookJs(path):
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    return src


def mkDir(filePath):
    tmpPath = filePath

    mkDirArr = []
    while 1:
        if os.path.exists(tmpPath):
            break
        else:
            mkDirArr.append(tmpPath)
        tmpPath = os.path.split(tmpPath)[0]

    mkDirArr.reverse()
    if len(mkDirArr) != 0:
        for mkPath in mkDirArr:
            try:
                os.mkdir(mkPath)
            except OSError:
                if not os.path.exists(mkPath):
                    raise Exception("Error: create directory {0} failed.".format(mkPath))


class CallBackCls:

    def __init__(self, callType, rootPath, dirPath="", script=None):
        """

        :param callType: 0 = d, 1 = m; Optional parameters
        :param rootPath: list or str; Required parameters, NO default
        :param script: fridaScript; if callType = 1/2 then Required parameters, NO default else None
        """

        if rootPath is None:
            logger.error("pathError")
            exit(-1)

        self.script = script
        self.END = False
        self.filePathDict = {}
        self.rootPath = rootPath

        if callType == 0:
            pass
        elif callType == 1:

            for path in depthIteratePath([".js"]).getDepthDir(dirPath):
                self.filePathDict[os.path.relpath(path, dirPath)] = path  # any exts files
        else:
            logger.error("callTypeError: {0}".format(callType))
            exit(-1)

    def dumpCallback(self, message, data):
        """
        dump js CallBack

        :param message: payload
        :param data:
        :return: None
        """
        msg = message["payload"]
        if msg["Status"] == "END":  # delay return
            self.END = True
            ColorPrinter.print_white_text("        DONE! Auto Exit")
            return
        if msg["Status"] == "Warning":  # evalString func is not unique
            logger.warning("Hook Ptr is not unique.")
            # return

        if msg["Status"] == "hookOn" and msg["Path"] is not None:
            logger.info("grip file: {0}, size: {1}".format(msg["Path"], msg["Size"]))

            filePath = os.path.join(self.rootPath, msg["Path"]).replace("\\", "/")

            mkDir(os.path.split(filePath)[0])

            if filePath.endswith("c"):
                filePath = filePath[:-1]

            with open(filePath, "wb") as p:
                p.write(msg["Data"].encode())

            logger.success("Save file: {0}, size: {1}".format(filePath, msg["Size"]))

    def replaceCallback(self, message, data):
        """
        dump js CallBack

        :param message: payload
        :param data:
        :return: None
        """
        msg = message["payload"]
        if msg["Status"] == "END":  # delay return
            self.END = True
            ColorPrinter.print_white_text("        DONE! Auto Exit")
            return
        elif msg["Status"] == "Warning":  # evalString func is not unique
            logger.warning(msg["Msg"])
            # return

        elif msg["Status"] == "Wait" and msg["Path"] is not None:
            if msg["Path"].endswith("c"):
                hookName = msg["Path"][:-1].replace("/", "\\")
            else:
                hookName = msg["Path"].replace("/", "\\")

            if self.filePathDict[hookName] != "":
                data = readHookJs(self.filePathDict[hookName])
                size = hex(len(data))
                self.script.post({'type': 'input', 'payload': {"Status": "Replace", "Data": data, "Size": size}})

        elif msg["Status"] == "replaceOk":
            logger.success("replace: {0}".format(msg["Path"]))

        else:
            self.script.post({'type': 'input', 'payload': {"Status": "Error"}})


def mainProcess():
    runPath = os.path.dirname(sys.argv[0])
    instruct = sys.argv[1]  # d/r/m
    hookPackageName = sys.argv[2]  # app packages
    try:
        ownPath = sys.argv[3]
    except IndexError:
        ownPath = None

    if len(sys.argv) < 3:
        print("\nThis is a tool for reverse engineering cocos2djs Apps")
        ColorPrinter.print_white_text("Usage : ")
        print("        python {0} [-d] [PackageName]".format(sys.argv[0]))
        # print("        python {0} [-r] [PackageName] [filePath]".format(sys.argv[0]))
        print("        python {0} [-m] [PackageName]".format(sys.argv[0]))

        ColorPrinter.print_white_text("Example : ")
        print("        python {0} -d com.mas0n.testApp".format(sys.argv[0]))
        ColorPrinter.print_white_text("Tips : ")
        print("        -d [-dump]")
        # print("        -r [-replace]")
        print("        -m [-replace all file in dir]")

        print("        If you want to specify a folder replacement, You can add optional parameters: [absDir]")
        print("        Support: dump .jsc files/local overrides\n")
        print("        If you have any questions, please contact [ MasonShi@88.com ]\n")
        exit(0)

    # hookPackageName = "com.zhise.cgdyj"

    if ownPath is None:
        rootPath = os.path.join(runPath, hookPackageName)
    else:
        rootPath = os.path.join(ownPath, hookPackageName)


    mkDir(rootPath)  # make new path dir

    device = frida.get_usb_device()
    pid = device.spawn([hookPackageName])
    session = device.attach(pid)
    device.resume(pid)

    if instruct[1:2] == "d":
        jsCode = readHookJs("scripts/dumpHook.js")
        script = session.create_script(jsCode)

        callCls = CallBackCls(0, rootPath)
        callBack = callCls.dumpCallback

    else:
        if ownPath is None:
            ownPath = os.path.join(runPath, hookPackageName)

        jsCode = readHookJs("scripts/replaceHook.js")
        script = session.create_script(jsCode)

        callCls = CallBackCls(1, runPath, ownPath, script)
        callBack = callCls.replaceCallback

    script.on("message", callBack)
    script.load()

    while not callCls.END:  # wait stop
        time.sleep(1)


if __name__ == "__main__":
    mainProcess()
