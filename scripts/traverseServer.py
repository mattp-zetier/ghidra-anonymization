### Import from here to perform an action on all files on the ghidra server or in a sub-directory
from __main__ import state

def _runFunctionRecursively(func, parent, *args, **kwargs):
    for ghidraFile in parent.getFiles():
        func(ghidraFile, *args, **kwargs)
    
    for folder in parent.getFolders():
        _runFunctionRecursively(func, folder, *args, **kwargs)


def runFunction(func, subFolder=None, *args, **kwargs):
    rootFolder = state.getProject().getProjectData().getRootFolder()
    if subFolder:
        folder = rootFolder.getFolder(subFolder)
    else:
        folder = rootFolder
    _runFunctionRecursively(func, folder, *args, **kwargs)


def main():

    def printFolder(ghidraFile):
        print(ghidraFile.getPathname())

    runFunction(func=printFolder)


if __name__ == "__main__":
    main()
