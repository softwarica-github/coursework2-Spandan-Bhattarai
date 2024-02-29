import subprocess
def main():
    print("Choose an option:")
    print("1. GUI Version")
    print("2. CLI Version")

    choice = input("Enter your choice: ")

    if choice == "1":
        import antivirus
        antivirus.main()
    elif choice == "2":
        file_path = input("Enter the path to the file: ")
        extra = int(input ("Enter 1 if you want to scan the file on virustotal as well: "))
        if extra==1:
            subprocess.call(["python", "cli.py", "--scan-virustotal", file_path])
        else:
            subprocess.call(["python", "cli.py", file_path])
    else:
        print("Invalid choice. Please choose again.")

if __name__ == "__main__":
    main()
