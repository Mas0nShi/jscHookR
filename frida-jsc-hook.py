import os
from argparse import ArgumentParser
from jscHookR2.core import Callback


NOW_PATH = os.path.dirname(os.path.abspath(__file__))

if __name__ == '__main__':
    p = ArgumentParser(description='Hook cocos2d-js engine to dump or replace .jsc files')
    p.add_argument('-p', '--package', help='android package name')
    p.add_argument('-t', '--timeout', help='timeout (default: 5s), use 0 to disable timeout', default=5, type=int)

    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--dump', help='dump .jsc files', action='store_true')
    group.add_argument('-r', '--replace', help='replace .jsc files or (no filename) script', action='store_true')

    group = p.add_mutually_exclusive_group()
    group.add_argument('-o', '--output', help='output directory (default: current directory), e.g. "*/{packageName}"', default=NOW_PATH)
    group.add_argument('-i', '--input', help='input directory (default: current directory)')

    args = p.parse_args()

    if args.dump:
        if not args.output:
            p.error('output directory is required')
    elif args.replace:
        if not args.input:
            p.error('input directory is required')

    callback = Callback(args.package, args.timeout, args.output, args.input)

    if args.dump:
        callback.dump()
    elif args.replace:
        callback.repl()

