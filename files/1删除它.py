import os
import hashlib
import shutil
from collections import defaultdict
from pathlib import Path

# File extensions for various categories
IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']
VIDEO_EXTENSIONS = ['.mp4', '.mkv', '.avi', '.mov', '.flv', '.wmv']
AUDIO_EXTENSIONS = ['.mp3', '.wav', '.flac', '.aac', '.ogg']
OFFICE_EXTENSIONS = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
CODE_EXTENSIONS = ['.py', '.c', '.cpp', '.rs']

def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def scan_directory_for_files(source_directory):
    """Scan a directory and categorize the files."""
    categorized_files = defaultdict(list)
    for root, _, files in os.walk(source_directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_extension = os.path.splitext(file)[1].lower()
            if file_extension in IMAGE_EXTENSIONS:
                categorized_files['images'].append(file_path)
            elif file_extension in VIDEO_EXTENSIONS:
                categorized_files['videos'].append(file_path)
            elif file_extension in AUDIO_EXTENSIONS:
                categorized_files['audio'].append(file_path)
            elif file_extension in OFFICE_EXTENSIONS:
                categorized_files['office'].append(file_path)
            elif file_extension in CODE_EXTENSIONS:
                categorized_files['code'].append(file_path)
    return categorized_files

def get_unique_filename(file_path, target_directory):
    """Generate a unique filename if a file with the same name already exists."""
    base_name = os.path.basename(file_path)
    new_name = base_name
    counter = 1
    while os.path.exists(os.path.join(target_directory, new_name)):
        name, extension = os.path.splitext(base_name)
        new_name = f"{name}_{counter}{extension}"
        counter += 1
    return new_name

def copy_or_move_file(file_path, target_directory, move=True):
    """Copy or move a file to the target directory based on the user's choice."""
    new_name = get_unique_filename(file_path, target_directory)
    new_path = os.path.join(target_directory, new_name)
    
    if move:
        print(f"Moving file {file_path} to {new_path}")
        shutil.move(file_path, new_path)
    else:
        print(f"Copying file {file_path} to {new_path}")
        shutil.copy(file_path, new_path)

def move_or_copy_files(categorized_files, target_directory, move=True):
    """Move or copy files to the target directory."""
    for category, files in categorized_files.items():
        for file in files:
            copy_or_move_file(file, target_directory, move)

def scan_directory_for_duplicates(target_directory):
    """Scan the target directory and find duplicate files based on their hash values."""
    hash_dict = defaultdict(list)
    for root, _, files in os.walk(target_directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_file_hash(file_path)
            hash_dict[file_hash].append(file_path)
    
    duplicates = {key: value for key, value in hash_dict.items() if len(value) > 1}
    return duplicates

def ask_user_to_delete_duplicates(duplicates):
    """Prompt the user to delete duplicate files."""
    if not duplicates:
        print("No duplicate files found.")
        return
    
    for file_hash, files in duplicates.items():
        print(f"The following files have the same hash value:")
        for file in files:
            print(f"- {file}")
        
        answer = input("Do you want to delete these duplicate files? (y/n): ")
        if answer.lower() == 'y':
            for file in files[1:]:  # Delete all but the first file
                print(f"Deleting file: {file}")
                os.remove(file)

def main():
    # Step 1: Scan the source directory and categorize files
    source_directory = input("Enter the source directory path: ")
    categorized_files = scan_directory_for_files(source_directory)
    
    # Step 2: Display the operation summary
    print("The following file types will be processed:")
    for category, files in categorized_files.items():
        print(f"{category.capitalize()}: {len(files)} files")
    
    # Step 3: Ask the user whether to start organizing files
    proceed = input("Do you want to organize the files into the target directory? (y/n): ")
    if proceed.lower() != 'y':
        print("Operation canceled.")
        return

    # Step 4: Ask the user whether to copy or move the files
    action = input("Choose action: Copy files (c) or Move files (m): ").strip().lower()
    if action == 'm':
        move_files = True
    elif action == 'c':
        move_files = False
    else:
        print("Invalid choice. Operation canceled.")
        return

    # Step 5: Move or copy the files to the target directory
    target_directory = input("Enter the target directory path: ")
    move_or_copy_files(categorized_files, target_directory, move_files)

    # Step 6: Scan the target directory for duplicates and hash values
    duplicates = scan_directory_for_duplicates(target_directory)

    # Step 7: Ask the user whether to delete duplicate files
    ask_user_to_delete_duplicates(duplicates)
    print("Operation completed.")

if __name__ == "__main__":
    main()







import tkinter as tk
from tkinter import filedialog, messagebox
import os
import shutil
import hashlib
import threading
from collections import defaultdict

# File extensions for various categories
IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']
VIDEO_EXTENSIONS = ['.mp4', '.mkv', '.avi', '.mov', '.flv', '.wmv']
AUDIO_EXTENSIONS = ['.mp3', '.wav', '.flac', '.aac', '.ogg']
OFFICE_EXTENSIONS = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
CODE_EXTENSIONS = ['.py', '.c', '.cpp', '.rs']

def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file to identify duplicates."""
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as file:
        # Read file in chunks to avoid memory overload
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def scan_directory_for_files(source_directory):
    """Scan a directory and categorize files into images, videos, etc."""
    categorized_files = defaultdict(list)
    # Walk through the directory and its subdirectories
    for root, _, files in os.walk(source_directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_extension = os.path.splitext(file)[1].lower()
            # Categorize files by their extensions
            if file_extension in IMAGE_EXTENSIONS:
                categorized_files['images'].append(file_path)
            elif file_extension in VIDEO_EXTENSIONS:
                categorized_files['videos'].append(file_path)
            elif file_extension in AUDIO_EXTENSIONS:
                categorized_files['audio'].append(file_path)
            elif file_extension in OFFICE_EXTENSIONS:
                categorized_files['office'].append(file_path)
            elif file_extension in CODE_EXTENSIONS:
                categorized_files['code'].append(file_path)
    return categorized_files

def get_unique_filename(file_path, target_directory):
    """Generate a unique filename if a file with the same name already exists."""
    base_name = os.path.basename(file_path)
    new_name = base_name
    counter = 1
    while os.path.exists(os.path.join(target_directory, new_name)):
        # Add a number suffix to make the filename unique
        name, extension = os.path.splitext(base_name)
        new_name = f"{name}_{counter}{extension}"
        counter += 1
    return new_name

def copy_or_move_file(file_path, target_directory, move=True):
    """Copy or move a file to the target directory based on the user's choice."""
    new_name = get_unique_filename(file_path, target_directory)
    new_path = os.path.join(target_directory, new_name)
    
    if move:
        # Move the file to the new location
        shutil.move(file_path, new_path)
    else:
        # Copy the file to the new location
        shutil.copy(file_path, new_path)

def move_or_copy_files(categorized_files, target_directory, move=True):
    """Process categorized files and move or copy them."""
    for category, files in categorized_files.items():
        for file in files:
            # Call function to move or copy each file
            copy_or_move_file(file, target_directory, move)

def scan_directory_for_duplicates(target_directory):
    """Scan the target directory and find duplicate files based on their hash values."""
    hash_dict = defaultdict(list)
    # Walk through the target directory to gather all files
    for root, _, files in os.walk(target_directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_file_hash(file_path)
            # Store the hash value as the key, and the file paths as the value
            hash_dict[file_hash].append(file_path)
    
    # Find duplicates (more than one file with the same hash)
    duplicates = {key: value for key, value in hash_dict.items() if len(value) > 1}
    return duplicates

def ask_user_to_delete_duplicates(duplicates):
    """Prompt the user to delete duplicate files."""
    if not duplicates:
        return "No duplicate files found."
    
    for file_hash, files in duplicates.items():
        # Show the files with the same hash value
        response = messagebox.askyesno("Delete Duplicate Files", f"The following files have the same hash value:\n" + "\n".join(files) + "\nDo you want to delete these duplicate files?")
        if response:
            for file in files[1:]:  # Delete all but the first file
                os.remove(file)
            return "Duplicate files deleted."
    return "Operation cancelled."

class FileOrganizerApp:
    def __init__(self, root):
        """Initialize the GUI application."""
        self.root = root
        self.root.title("File Organizer")
        self.root.geometry("600x400")  # Window size
        self.root.configure(bg="#FFD700")  # Gold color background

        # Font and color settings
        self.font = ('Arial', 14)
        self.font_color = "#3C0000"  # RGB 60, 0, 0

        # Source and target directory variables
        self.source_directory = ""
        self.target_directory = ""

        self.create_widgets()

    def create_widgets(self):
        """Create and display the widgets (buttons, labels)."""
        # Title Label
        title_label = tk.Label(self.root, text="File Organizer", font=('Arial', 18, 'bold'), fg=self.font_color, bg="#FFD700")
        title_label.pack(pady=20)

        # Source Directory Button
        self.source_button = tk.Button(self.root, text="Choose Source Directory", font=self.font, fg=self.font_color, bg="#FFD700", command=self.choose_source_directory)
        self.source_button.pack(pady=10)

        # Target Directory Button
        self.target_button = tk.Button(self.root, text="Choose Target Directory", font=self.font, fg=self.font_color, bg="#FFD700", command=self.choose_target_directory)
        self.target_button.pack(pady=10)

        # Move Files Button
        self.move_button = tk.Button(self.root, text="Move Files", font=self.font, fg=self.font_color, bg="#FFD700", command=self.start_move_files_thread)
        self.move_button.pack(pady=10)

        # Copy Files Button
        self.copy_button = tk.Button(self.root, text="Copy Files", font=self.font, fg=self.font_color, bg="#FFD700", command=self.start_copy_files_thread)
        self.copy_button.pack(pady=10)

        # Output Label
        self.output_label = tk.Label(self.root, text="Choose directories and start organizing.", font=self.font, fg=self.font_color, bg="#FFD700")
        self.output_label.pack(pady=20)

    def choose_source_directory(self):
        """Open a dialog to choose the source directory."""
        self.source_directory = filedialog.askdirectory(title="Select Source Directory")
        if self.source_directory:
            self.output_label.config(text=f"Source Directory: {self.source_directory}")

    def choose_target_directory(self):
        """Open a dialog to choose the target directory."""
        self.target_directory = filedialog.askdirectory(title="Select Target Directory")
        if self.target_directory:
            self.output_label.config(text=f"Target Directory: {self.target_directory}")

    def start_move_files_thread(self):
        """Start the file moving operation in a separate thread."""
        if not self.source_directory or not self.target_directory:
            messagebox.showerror("Error", "Please select both source and target directories.")
            return
        # Start a new thread for moving files
        threading.Thread(target=self.move_files).start()

    def start_copy_files_thread(self):
        """Start the file copying operation in a separate thread."""
        if not self.source_directory or not self.target_directory:
            messagebox.showerror("Error", "Please select both source and target directories.")
            return
        # Start a new thread for copying files
        threading.Thread(target=self.copy_files).start()

    def move_files(self):
        """Move files from source to target directory."""
        # Scan and categorize files
        categorized_files = scan_directory_for_files(self.source_directory)

        # Move or copy files
        move_or_copy_files(categorized_files, self.target_directory, move=True)

        # Check duplicates and prompt user
        duplicates = scan_directory_for_duplicates(self.target_directory)
        result = ask_user_to_delete_duplicates(duplicates)
        messagebox.showinfo("Result", result)

    def copy_files(self):
        """Copy files from source to target directory."""
        # Scan and categorize files
        categorized_files = scan_directory_for_files(self.source_directory)

        # Move or copy files
        move_or_copy_files(categorized_files, self.target_directory, move=False)

        # Check duplicates and prompt user
        duplicates = scan_directory_for_duplicates(self.target_directory)
        result = ask_user_to_delete_duplicates(duplicates)
        messagebox.showinfo("Result", result)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileOrganizerApp(root)
    root.mainloop()


This program is being debugged, and it has not been completely tested successfully. 
