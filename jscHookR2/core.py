import os
import frida
import pathlib
import hashlib
import shutil
from enum import Enum
from loguru import logger


def md5sum(content: str) -> str:
    m = hashlib.md5()
    m.update(content.encode('utf-8'))
    return m.hexdigest()


def hex_upper(sz: int) -> str:
    return hex(sz).upper().replace('0X', '0x')


class StatusEnum(Enum):
    log = 'log'
    warn = 'warn'
    callback = 'callback'
    stop = 'stop'
    done = 'done'
    skip = 'skip'
    next = 'next'


class CallbackResult:
    scripts: str
    size: int
    filename: str

    def __init__(self, scripts: str, size: int, filename: str):
        self.scripts = scripts
        self.size = size
        self.filename = filename

    @property
    def sz(self) -> str:
        return hex_upper(self.size) if self.size >= 0 else str(self.size)

    @property
    def hash(self) -> str:
        return md5sum(self.scripts)


class ReceiveMessage:
    """
    {'type': 'send', 'payload': {'status': 'stop', 'msg': 'detect the cocos2d-js script lazy loaded, auto stop the script.'}}
    {'type': 'send', 'payload': {'status': 'callback', 'callback': {'scripts': 'ADNativeBridage.SignnBlockUser(2101)', 'size': 4294967295, 'filename': None}}}
    """

    def __init__(self, message: dict):
        if message.get('type') == 'error':
            raise Exception(message.get('stack', 'unknown error'))
        self.payload = message.get('payload', {})
        if not self.payload:
            raise Exception('receive message payload is empty')

    @property
    def status(self) -> StatusEnum:
        return StatusEnum(self.payload["status"])

    @property
    def is_callback(self) -> bool:
        return self.status == StatusEnum.callback

    @property
    def is_warn(self) -> bool:
        return self.status == StatusEnum.warn

    @property
    def is_log(self) -> bool:
        return self.status == StatusEnum.log

    @property
    def is_stop(self) -> bool:
        return self.status == StatusEnum.stop

    @property
    def is_done(self) -> bool:
        return self.status == StatusEnum.done

    @property
    def message(self) -> str:
        return self.payload["msg"] if "msg" in self.payload else 'no message'

    @property
    def callback(self) -> CallbackResult | None:
        if self.is_callback or self.is_done:
            return CallbackResult(**self.payload["callback"])
        else:
            return None


class PostMessage:
    status: StatusEnum
    msg: str
    callback: dict

    def __init__(self, status: StatusEnum, msg: str = None, callback: dict = None):
        self.status = status
        self.msg = msg
        self.callback = callback

    def to_dict(self):
        return {
            "status": self.status.value,
            "msg": self.msg,
            "callback": self.callback
        }


class Callback:
    out_dir: pathlib.Path
    input_dir: pathlib.Path | None

    session: frida.core.Session
    dump_script: frida.core.Script
    repl_script: frida.core.Script
    stop: bool = False


    def __init__(self, packageName: str, timeOut: int, out_dir: str | None = None, input_dir: str | None = None):
        device = frida.get_usb_device()
        pid = device.spawn([packageName])
        self.session = device.attach(pid)
        device.resume(pid)

        self.out_dir = pathlib.Path(out_dir) / packageName
        if input_dir:
            self.input_dir = pathlib.Path(input_dir)
        else:
            self.input_dir = None

        dump_script = open(pathlib.Path(__file__).parent / 'scripts' / 'dump.js', 'r').read()
        repl_script = open(pathlib.Path(__file__).parent / 'scripts' / 'repl.js', 'r').read()

        if timeOut:
            dump_script += f'\nsetImmediate(function(){{ setTimeout(hook, 10); delay(false, {timeOut});}})'
            repl_script += f'\nsetImmediate(function(){{ setTimeout(hook, 10); delay(false, {timeOut});}})'
        else:
            dump_script += f'\nsetImmediate(function(){{ setTimeout(hook, 10);}})'
            repl_script += f'\nsetImmediate(function(){{ setTimeout(hook, 10);}})'

        self.dump_script = self.session.create_script(dump_script)
        self.repl_script = self.session.create_script(repl_script)

    def _dump_callback(self, message, data):
        """
        dump js CallBack

        :param message: payload
        :param data:
        :return: None
        """
        msg = ReceiveMessage(message)

        if msg.is_stop:
            self.stop = True
            logger.info(msg.message)
            return

        if msg.is_warn:
            logger.warning(msg.message)
            return

        if msg.is_callback:
            callback = msg.callback
            if not callback.filename:
                callback.filename = os.path.join('no-filename', f'{callback.hash}.js')
                logger.warning(f'no filename, save use hash: {callback.filename}, size: {callback.sz}')
            else:
                logger.info(f'capture file: {callback.filename}, size: {callback.sz}')

            filename = callback.filename
            fpath = pathlib.Path(filename)
            if fpath.suffix == '.jsc':
                filename = fpath.with_suffix('.js')

            pathlib.Path(self.out_dir / fpath.parent).mkdir(parents=True, exist_ok=True)

            with open(self.out_dir / filename, 'w') as f:
                f.write(callback.scripts)

            logger.success(f'Save file: {filename}, size: {callback.sz}')

    def _repl_callback(self, message, data):
        """
        dump js CallBack

        :param message: payload
        :param data:
        :return: None
        """
        msg = ReceiveMessage(message)

        if msg.is_stop:
            self.stop = True
            logger.info(msg.message)
            return

        if msg.is_warn:
            logger.warning(msg.message)
            return

        if msg.is_log:
            logger.info(msg.message)
            return

        if msg.is_callback:
            callback = msg.callback
            if callback.filename is None:
                logger.warning(f'no filepath, use hash match: {callback.hash}')
                callback.filename = os.path.join('no-filename', f'{callback.hash}.js')

            logger.info(f'replace file: {callback.filename}')
            fpth = pathlib.Path(callback.filename)
            filename = fpth.with_suffix('.js') if fpth.suffix == '.jsc' else fpth
            # @IMPORTANT: read bytes length, not string length!
            content = pathlib.Path(self.input_dir / filename).read_bytes()
            self.repl_script.post({'type': 'callback', 'payload': {'status': StatusEnum.next.value, 'content': content.decode('utf-8'), 'size': len(content)}})
            return

        if msg.is_done:
            callback = msg.callback
            logger.success(f'replace done: {callback.filename or callback.hash + ".js"}')
            return

    def dump(self):
        if self.out_dir.exists():
            shutil.rmtree(self.out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

        self.dump_script.on('message', self._dump_callback)
        self.dump_script.load()
        while not self.stop:
            pass

        self.dump_script.unload()
        self.session.detach()

    def repl(self):
        if self.input_dir is None or not self.input_dir.exists():
            logger.error('input dir not exists')
            return

        self.repl_script.on('message', self._repl_callback)
        self.repl_script.load()
        while not self.stop:
            pass

        self.repl_script.unload()
        self.session.detach()
