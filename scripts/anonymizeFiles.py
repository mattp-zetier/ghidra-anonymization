#@menuPath Scripts.anonymizeFiles
# Anonymize the FSRL and file path of all files in a Ghidra server project
from anonymizeFile import anonymizeProgram
from traverseServer import runFunction


def anonymizeFile(ghidraFile):
    print(ghidraFile.getPathname())
    program = ghidraFile.getDomainObject(this, True, False, None)
    tx = program.startTransaction("Anonymizing program")
    try:
        anonymizeProgram(program)
        program.endTransaction(tx, True)   # Commit
    except Exception as ex:
        program.endTransaction(tx, False)  # Do not commit
    program.release(this)


def anonymizeAllFiles():
    runFunction(anonymizeFile)


def main():
    anonymizeAllFiles()


if __name__ == "__main__":
    main()
