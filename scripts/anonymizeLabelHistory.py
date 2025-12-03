#@menuPath Scripts.anonymizeLabelHistory
# Replace the username field of all label history entries with a new value provided by the user

    
def anonymizeLabelHistory(program, anonymousUsername):
    num_anonymized = program.getSymbolTable().anonymizeLabelHistory(anonymousUsername)
    print("Anonymized {} labels".format(num_anonymized))


def main():
    anonymousUsername = askString("Anonymous Username", "Enter the username to replace existing label authors with:", "Anonymized")
    anonymizeLabelHistory(currentProgram, anonymousUsername)


if __name__ =="__main__":
    main()
