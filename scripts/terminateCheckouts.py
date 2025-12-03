#@menupath Scripts.terminateCheckouts
# Forcibly remove checkouts
# Defaults to terminating checkouts for all binaries on the server
# A subdirectory can be given on the commandline: -postScript terminateCheckouts.py <subFolder>


def terminateCheckouts(repo, file):

    # Result of a checkout containing uncommited changes being versioned
    if file.getPathname().endswith(".keep"):
        print("Skipping .keep file")
        return

    try:
        checkouts = file.getCheckouts()
    except Exception as ex:
        # Probably a local file that hasn't been checked into the server yet
        print("Could not get checkouts, file may not be versioned, skipping")
        return

    numCheckouts = len(checkouts)
    print("Checkouts: {}".format(numCheckouts))
    for checkout in checkouts:
        repo.terminateCheckout(file.getParent().getPathname(), file.getName(), checkout.getCheckoutId(), False)


def terminateCheckoutsRecursively(repo, parent):
    for file in parent.getFiles():
        print(file.getPathname())
        terminateCheckouts(repo, file)
    for folder in parent.getFolders():
        terminateCheckoutsRecursively(repo, folder)


def main():
    projectData = state.getProject().getProjectData()
    repo = projectData.getRepository()
    if not repo:
        print("[!] Could not get a handle to the repo, exiting")
        return

    rootFolder = projectData.getRootFolder()
    folder = rootFolder

    args = getScriptArgs()
    if len(args) == 1:
        folder = rootFolder.getFolder(args[0])

    terminateCheckoutsRecursively(repo, folder)


if __name__ == "__main__":
    main()
