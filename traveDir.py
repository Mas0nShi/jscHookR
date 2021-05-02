import os


class depthIteratePath:

    def __init__(self, exts=[]):
        self._files = []
        self._exts = exts

    def _deepIterateDir(self, rootDir):
        for lists in os.listdir(rootDir):
            path = os.path.join(rootDir, lists)
            if os.path.isdir(path):
                self._deepIterateDir(path)
            elif os.path.isfile(path):
                ext = os.path.splitext(path)[1]
                if ext in self._exts:
                    self._files.append(path)

    def getDepthDir(self, rootPath):
        self._deepIterateDir(rootPath)
        return self._files