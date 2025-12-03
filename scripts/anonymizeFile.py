#@menupath Scripts.anonymizeFile
# Files on a Ghidra server contain metadata detailing the original path on disk at upload time
# This means that if the files were uploaded from a home directory (as they often are), identifying information will be included
# This script will scrub the paths, changing them to the path to the file from the root of the repository
from ghidra.program.model.listing import Program
from ghidra.formats.gfilesystem import FSRL


def printPathAndFsrl(program, options):
    currentPath = program.getExecutablePath()
    currentFsrl = options.getString(FSRL.FSRL_OPTION_NAME, None)
    print("Executable Path - {}".format(currentPath))
    print("FSRL -            {}".format(currentFsrl))


def anonymizeProgram(program):
    options = program.getOptions(Program.PROGRAM_INFO)

    print("Before:")
    printPathAndFsrl(program, options)

    # Change executable path from the local path at upload-time to the path on the Ghidra server
    # Change FSRL to the same, and preserve the MD5 hash
    currentFsrl = options.getString(FSRL.FSRL_OPTION_NAME, None)
    pathname = program.getDomainFile().getPathname()
    md5 = currentFsrl.split("MD5=")[1].strip()
    newFsrl = "file://{}?MD5={}".format(pathname, md5)
    program.setExecutablePath(pathname)
    options.setString(FSRL.FSRL_OPTION_NAME, newFsrl)

    # Visual confirmation the changes stuck
    print("After:")
    printPathAndFsrl(program, options)


def main():
    anonymizeProgram(currentProgram)


if __name__ == "__main__":
    main()

