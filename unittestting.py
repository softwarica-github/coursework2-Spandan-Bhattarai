import unittest
from unittest.mock import patch, MagicMock
import tkinter as tk
from tkinter import filedialog
from antivirus import VirusCheckerApp

class TestVirusCheckerApp(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.app = VirusCheckerApp(self.root)

    def tearDown(self):
        self.root.destroy()

    @patch('antivirus.filedialog.askopenfilename') 
    def test_select_file(self, mock_askopenfilename):
        mock_askopenfilename.return_value = "/path/to/testfile.txt"
        self.app.select_file()
        self.assertEqual(self.app.file_entry.get(), "/path/to/testfile.txt")

    @patch('antivirus.os.path.basename')
    @patch('antivirus.os.path.exists')
    @patch('antivirus.os.remove')
    @patch('antivirus.messagebox.showinfo')
    def test_delete_file(self, mock_showinfo, mock_remove, mock_exists, mock_basename):
        mock_exists.return_value = True
        mock_basename.return_value = "testfile.txt"
        self.app.file_entry.insert(tk.END, "/path/to/testfile.txt")
        self.app.delete_file()
        mock_remove.assert_called_once_with("/path/to/testfile.txt")
        mock_showinfo.assert_called_once()

    @patch('antivirus.messagebox.showerror')
    def test_delete_file_no_file_selected(self, mock_showerror):
        self.app.delete_file()
        mock_showerror.assert_called_once()

if __name__ == '__main__':
    unittest.main()
