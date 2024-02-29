import argparse
import hashlib
import os
import requests
import pyfiglet
from termcolor import colored

class VirusCheckerCLI:
    def __init__(self):
        self.parse_arguments()

    def parse_arguments(self):
        parser = argparse.ArgumentParser(description="Virus Checker CLI")
        parser.add_argument("file_path", help="Path to the file to check for viruses")
        parser.add_argument("--scan-virustotal", action="store_true", help="Scan file in VirusTotal")
        args = parser.parse_args()

        self.file_path = args.file_path
        self.scan_virustotal = args.scan_virustotal

        self.check_for_virus()

    def calculate_file_hash(self):
        """Calculate the hash of a file."""
        hash_md5 = hashlib.md5()
        with open(self.file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def check_for_virus(self):
        """Check if the file hash matches any hash in the list."""
        if not os.path.exists(self.file_path):
            print("Error: File not found.")
            return

        file_name = os.path.basename(self.file_path)
        file_hash = self.calculate_file_hash()
        virus_detected = False

        if file_hash in self.get_hash_list():
            virus_detected = True

        if virus_detected:
            print("Virus Detected")
        else:
            print("File is Safe")

        if self.scan_virustotal:
            self.search_virustotal(file_hash)

    def get_hash_list(self):
        hash_files = [
            "hashes/SHA256-Hashes_pack1.txt",
            "hashes/SHA256-Hashes_pack2.txt",
            "hashes/SHA256-Hashes_pack3.txt"
        ]
        hash_list = set()
        for hash_file in hash_files:
            with open(hash_file, 'r') as f:
                hashes = f.read().split(';')
                hash_list.update(hashes)
        return hash_list

    def search_virustotal(self, file_hash):
        url = f'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': 'e65ac6804ffb37d609f0ea91d3c04a833b3f5a4866efd71b56e82e3c33e432f4', 'resource': file_hash}
        response = requests.get(url, params=params)
        if response.status_code == 200:
            result = response.json()
            if result['response_code'] == 1:
                self.display_virustotal_result(result['positives'], result['total'])
            else:
                self.display_virustotal_result("File not found in VirusTotal database")
        else:
            self.display_virustotal_result("Error occurred while querying VirusTotal")

    def display_virustotal_result(self, *args):
        if len(args) == 2:
            positives, total = args
            result_text = f"VirusTotal Result: Detected {positives} out of {total} scanners"
        else:
            result_text = args[0]
        print(result_text)

def main():
    font = pyfiglet.Figlet(font='slant')
    print(colored(font.renderText('         Web'),'red'))
    print(colored(font.renderText('Enumerator'),'red'))

    print(" "*38,"BY Spandan Bhattarai",)
    print("[+] Github: https://github.com/Spandan-Bhattarai\n")

    VirusCheckerCLI()

if __name__ == "__main__":
    main()