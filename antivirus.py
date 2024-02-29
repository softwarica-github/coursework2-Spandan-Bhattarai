import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import os
import requests

class VirusCheckerApp:
    current_dir = os.path.dirname(__file__)
    SHA256_HASHES_pack1 = os.path.join(current_dir, 'hashes', 'SHA256-Hashes_pack1.txt')
    SHA256_HASHES_pack2 = os.path.join(current_dir, 'hashes', 'SHA256-Hashes_pack2.txt')
    SHA256_HASHES_pack3 = os.path.join(current_dir, 'hashes', 'SHA256-Hashes_pack3.txt')

    def __init__(self, master):
        self.master = master
        master.title("Virus Checker")
        master.geometry("600x350")
        master.resizable(False, False)

        self.nav_bar = tk.Frame(master, bg="gray", height=30)
        self.nav_bar.pack(fill="x")
        self.home_label = tk.Label(self.nav_bar, text="                                                                    Home", bg="gray", fg="white", font=("Helvetica", 12))
        self.home_label.pack(side="left", padx=10, pady=5)

        # Frame for file selection
        self.file_frame = ttk.Frame(master)
        self.file_frame.pack(pady=20)

        # File selection entry and button
        self.file_entry = ttk.Entry(self.file_frame, width=60, font=("Helvetica", 10))
        self.file_entry.grid(row=0, column=0, padx=5, pady=5)
        self.file_button = ttk.Button(self.file_frame, text="Select File", command=self.select_file)
        self.file_button.grid(row=0, column=1, padx=5, pady=5)

        self.scan_virustotal_var = tk.BooleanVar()
        self.scan_virustotal_checkbox = ttk.Checkbutton(master, text="Scan in VirusTotal", variable=self.scan_virustotal_var)
        self.scan_virustotal_checkbox.pack(pady=5)

        # Check virus button
        self.check_button = ttk.Button(master, text="Check for Virus", command=self.check_for_virus, style="Accent.TButton")
        self.check_button.pack(pady=10)

        # Delete file button
        self.delete_button = ttk.Button(master, text="Delete File", command=self.delete_file, style="Danger.TButton")
        self.delete_button.pack()
        self.delete_button.config(state="disabled")  # Disable initially

        # Clear button
        self.clear_button = ttk.Button(master, text="Clear", command=self.clear_file_info)
        self.clear_button.pack(padx=10, pady=5)
        self.clear_button.config(state="disabled")  # Disable initially

        # Labels for displaying file info
        self.file_name_label = ttk.Label(master, text="", font=("Helvetica", 10))
        self.file_name_label.pack(anchor="w", padx=20)
        self.file_path_label = ttk.Label(master, text="", font=("Helvetica", 10))
        self.file_path_label.pack(anchor="w", padx=20)
        self.file_hash_label = ttk.Label(master, text="", font=("Helvetica", 10))
        self.file_hash_label.pack(anchor="w", padx=20)
        self.virus_status_label = ttk.Label(master, text="", font=("Helvetica", 10, "bold"), foreground="red")
        self.virus_status_label.pack(anchor="w", padx=20, pady=10)
        self.virustotal_result_label = ttk.Label(master, text="", font=("Helvetica", 10))
        self.virustotal_result_label.pack(anchor="w", padx=20)

        #  custom styles for buttons
        self.master.style = ttk.Style()
        self.master.style.configure("Accent.TButton", foreground="black", background="#4CAF50", font=("Helvetica", 10, "bold"))
        self.master.style.map("Accent.TButton", background=[("active", "#45a049")])
        self.master.style.configure("Danger.TButton", foreground="black", background="#f44336", font=("Helvetica", 10, "bold"))
        self.master.style.map("Danger.TButton", background=[("active", "#d32f2f")])

    def select_file(self):
        """Open file dialog to select a file."""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(tk.END, file_path)
            self.delete_button.config(state="disabled")  # Disable the delete button for the new file
            self.clear_button.config(state="active")  # Enable the clear button
            self.clear_file_info()

    def calculate_file_hash(self, file_path):
        """Calculate the hash of a file."""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def check_for_virus(self):
        """Check if the file hash matches any hash in the list."""
        file_path = self.file_entry.get()
        
        if not file_path:
            messagebox.showerror("Error", "Please select a file.")
            return
        
        file_name = os.path.basename(file_path)
        file_hash = self.calculate_file_hash(file_path)
        virus_detected = False
        for hash_list_file in [self.SHA256_HASHES_pack1, self.SHA256_HASHES_pack2, self.SHA256_HASHES_pack3]:
            with open(hash_list_file, 'r') as f:
                hash_list = f.read().split(';')

            # Remove any leading/trailing whitespaces from each hash value
            hash_list = [hash_value.strip() for hash_value in hash_list]

            if file_hash in hash_list:
                virus_detected = True
                break
        
        if virus_detected:
            self.virus_status_label.config(text="Virus Detected", foreground="red")
            self.delete_button.config(state="active")
        else:
            self.virus_status_label.config(text="File is Safe", foreground="green")
            self.delete_button.config(state="disabled")


        
        if virus_detected:
            self.virus_status_label.config(text="Virus Detected", foreground="red")
            self.delete_button.config(state="active")
        else:
            self.virus_status_label.config(text="File is Safe", foreground="green")
            self.delete_button.config(state="disabled")
        
        if self.scan_virustotal_var.get():
            self.search_virustotal(file_hash)
        
        # Display file information
        self.file_name_label.config(text="File Name: " + file_name)
        self.file_path_label.config(text="File Path: " + file_path)
        self.file_hash_label.config(text="File Hash: " + file_hash)

        # Save output to output.txt
        with open("output.txt", "a") as f:
            f.write("File Name: " + file_name + "\n")
            f.write("File Path: " + file_path + "\n")
            f.write("File Hash: " + file_hash + "\n")
            f.write("Virus Status: " + ("Virus Detected" if virus_detected else "File is Safe") + "\n")
            f.write("\n")

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
        self.virustotal_result_label.config(text=result_text)

    def delete_file(self):
        """Delete the selected file."""
        file_path = self.file_entry.get()
        
        if not file_path:
            messagebox.showerror("Error", "No file selected.")
            return
        
        try:
            os.remove(file_path)
            messagebox.showinfo("File Deleted", f"The file {file_path} has been deleted successfully.")
            self.clear_file_info()
            self.delete_button.config(state="disabled")  # Disable the delete button after deletion
            self.clear_button.config(state="disabled")  # Disable the clear button after deletion
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete the file: {str(e)}")

    def clear_file_info(self):
        """Clear the file information labels."""
        self.file_name_label.config(text="")
        self.file_path_label.config(text="")
        self.file_hash_label.config(text="")
        self.virus_status_label.config(text="", foreground="black")
        self.virustotal_result_label.config(text="")

def main():
    root = tk.Tk()
    app = VirusCheckerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
