#@menuPath Scripts.anonymizeCommentHistory
# Replace the username field of all comment history entries with a new value provided by the user

def anonymizeCommentHistory(program, anonymousUsername):
    num_anonymized = program.getListing().anonymizeCommentHistory(anonymousUsername)
    print("Anonymized {} comments".format(num_anonymized))


def main():
    anonymousUsername = askString("Anonymous Username", "Enter the username to replace existing comment authors with:", "Anonymized")
    anonymizeCommentHistory(currentProgram, anonymousUsername)


if __name__ =="__main__":
    main()
