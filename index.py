def main():
    print("Choose an option:")
    print("1. GUI Version")
    print("2. CLI Version")

    choice = input("Enter your choice: ")

    if choice == "1":
        import antivirus
        antivirus.main()
    elif choice == "2":
        import cli
        cli.main()
    else:
        print("Invalid choice. Please choose again.")

if __name__ == "__main__":
    main()
