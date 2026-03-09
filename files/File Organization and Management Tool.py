import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import shutil
import hashlib
import threading
from collections import defaultdict
# =========================================================
# File extension groups
# Only these file types will be processed in the organizer.
# No "others" category is used.
# =========================================================
IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']
VIDEO_EXTENSIONS = ['.mp4', '.mkv', '.avi', '.mov', '.flv', '.wmv']
AUDIO_EXTENSIONS = ['.mp3', '.wav', '.flac', '.aac', '.ogg']
OFFICE_EXTENSIONS = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.txt']
COMPRESSED_EXTENSIONS = ['.zip', '.rar', '.7z', '.tar', '.gz']
# Map category folder names to supported extensions
CATEGORY_MAP = {
    'images': IMAGE_EXTENSIONS,
    'videos': VIDEO_EXTENSIONS,
    'audio': AUDIO_EXTENSIONS,
    'office': OFFICE_EXTENSIONS,
    'compressed': COMPRESSED_EXTENSIONS,
}
# =========================================================
# Hashing utilities
# =========================================================
def calculate_file_hash(file_path):
    """
    Calculate the SHA-256 hash of a file.
    Why this is needed:
    - We use file hashes to detect duplicate files by content.
    - This is more reliable than comparing file names.
    - Two files with different names can still be duplicates.
    - Two files with the same name may be completely different files.

    The file is read in chunks to avoid loading a large file into memory.
    """
    hash_sha256 = hashlib.sha256()

    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(8192), b""):
            hash_sha256.update(chunk)

    return hash_sha256.hexdigest()


# =========================================================
# Organizer helpers
# =========================================================
def get_file_category(file_name):
    """
    Return the target category for a file based on its extension.

    Returns:
    - category name string such as 'images', 'videos', etc.
    - None if the file extension is not one of the allowed types
    """
    ext = os.path.splitext(file_name)[1].lower()

    for category, extensions in CATEGORY_MAP.items():
        if ext in extensions:
            return category

    return None


def scan_directory_for_files(source_directory, target_directory=None):
    """
    Scan the source directory recursively and collect files by category.

    Important behavior:
    - Only files matching the allowed extension groups are collected.
    - Files outside those extension groups are ignored.
    - If the target directory is inside the source directory, the target
      directory is skipped during scanning to avoid processing already
      organized files again.

    Returns:
    - categorized_files: dict-like object
      Example:
      {
          'images': [path1, path2],
          'videos': [path3]
      }
    """
    categorized_files = defaultdict(list)
    target_abs = os.path.abspath(target_directory) if target_directory else None
    for root, dirs, files in os.walk(source_directory):
        root_abs = os.path.abspath(root)
        # If the current folder is exactly the target folder, do not scan it.
        if target_abs and root_abs == target_abs:
            dirs[:] = []
            continue
        # If the target folder is a child folder of the current root,
        # remove it from traversal so os.walk will not enter it.
        if target_abs:
            dirs[:] = [
                d for d in dirs
                if os.path.abspath(os.path.join(root, d)) != target_abs
            ]
        for file in files:
            file_path = os.path.join(root, file)
            category = get_file_category(file)
            if category is not None:
                categorized_files[category].append(file_path)
    return categorized_files
def ensure_category_directories(target_directory):
    """
    Create the category folders inside the target directory.

    Only the five required folders are created:
    - images
    - videos
    - audio
    - office
    - compressed
    """
    for category in CATEGORY_MAP.keys():
        os.makedirs(os.path.join(target_directory, category), exist_ok=True)


def build_existing_hash_map(target_directory):
    """
    Build a hash map for files already present in the target directory.

    Why this matters:
    - Before moving/copying a file, we want to know whether the target
      directory already contains the same content.
    - If the content already exists, we skip the file instead of storing
      another copy.

    Returns:
    - existing_hashes: dict {file_hash: file_path}
    """
    existing_hashes = {}
    for root, _, files in os.walk(target_directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                file_hash = calculate_file_hash(file_path)
                existing_hashes[file_hash] = file_path
            except Exception:
                # If a file cannot be hashed, skip it silently here.
                # Errors during active processing are logged later.
                pass
    return existing_hashes
def handle_single_file(file_path, category, target_directory, existing_hashes, move=True):
    """
    Process a single file for the organizer tab.

    Rules:
    - Do NOT rename files
    - Do NOT overwrite files
    - If identical content already exists in the target, skip the file
    - If a same-name file exists in the target:
        * same content -> skip
        * different content -> conflict, skip
    - If there is no conflict, copy or move the file

    Returns:
    - A human-readable log string describing the result
    """
    category_dir = os.path.join(target_directory, category)
    os.makedirs(category_dir, exist_ok=True)
    file_name = os.path.basename(file_path)
    target_path = os.path.join(category_dir, file_name)
    try:
        source_hash = calculate_file_hash(file_path)
    except Exception as e:
        return f"Failed: could not read source hash -> {file_path} ({e})"
    # If the same content already exists anywhere in the target directory,
    # skip the file completely.
    if source_hash in existing_hashes:
        return f"Skipped duplicate content: {file_path}"
    # If the target path already exists, check whether it is identical.
    if os.path.exists(target_path):
        try:
            target_hash = calculate_file_hash(target_path)
        except Exception as e:
            return f"Failed: could not read target hash -> {target_path} ({e})"
        if source_hash == target_hash:
            existing_hashes[source_hash] = target_path
            return f"Skipped same name / same content: {file_path}"
        else:
            return f"Conflict skipped: same name but different content -> {target_path}"
    # No duplicate and no name conflict: perform the operation.
    try:
        if move:
            shutil.move(file_path, target_path)
            action = "Moved"
        else:
            shutil.copy2(file_path, target_path)
            action = "Copied"

        existing_hashes[source_hash] = target_path
        return f"{action}: {file_path} -> {target_path}"

    except Exception as e:
        return f"Failed: {file_path} ({e})"


def process_files(categorized_files, target_directory, move=True, progress_callback=None):
    """
    Process all categorized files for the organizer tab.

    Parameters:
    - categorized_files: output from scan_directory_for_files
    - target_directory: destination root folder
    - move: True for move, False for copy
    - progress_callback: optional callback to report progress to the UI

    Returns:
    - logs: list of log strings
    """
    ensure_category_directories(target_directory)
    existing_hashes = build_existing_hash_map(target_directory)

    total_files = sum(len(files) for files in categorized_files.values())
    processed = 0
    logs = []

    for category, files in categorized_files.items():
        for file_path in files:
            result = handle_single_file(
                file_path=file_path,
                category=category,
                target_directory=target_directory,
                existing_hashes=existing_hashes,
                move=move
            )
            logs.append(result)
            processed += 1
            if progress_callback:
                progress_callback(processed, total_files, result)
    return logs
# =========================================================
# Duplicate cleaner helpers
# =========================================================
def scan_duplicates_in_directory(directory, progress_callback=None):
    """
    Recursively scan all files in a directory and group them by content hash.

    This function does NOT delete anything.
    It only builds a dictionary:
        {hash_value: [file1, file2, file3, ...]}

    Files sharing the same hash are duplicates by content.

    Returns:
    - hash_dict: dictionary of hash -> list of file paths
    - errors: list of scan error messages
    """
    all_files = []

    for root, _, files in os.walk(directory):
        for file in files:
            all_files.append(os.path.join(root, file))

    all_files.sort()
    total = len(all_files)

    hash_dict = defaultdict(list)
    errors = []

    for index, file_path in enumerate(all_files, start=1):
        try:
            file_hash = calculate_file_hash(file_path)
            hash_dict[file_hash].append(file_path)
            msg = f"Scanning: {index}/{total} -> {file_path}"
        except Exception as e:
            errors.append(f"Failed: could not hash file -> {file_path} ({e})")
            msg = f"Failed to read: {file_path}"
        if progress_callback:
            progress_callback(index, total, msg)
    return hash_dict, errors


def delete_duplicate_files(directory, progress_callback=None):
    """
    Delete duplicate files inside a directory tree.
    Duplicate rule:
    - Files are considered duplicates if their SHA-256 hash is identical.
    Retention rule:
    - For each duplicate group, keep exactly one file.
    - The kept file is the first file after sorting the paths.
    - All remaining files in that group are deleted.
    Cleanup rule:
    - After deleting duplicates, remove empty folders bottom-up.
    Returns a result dictionary containing counts, logs, and errors.
    """
    hash_dict, errors = scan_duplicates_in_directory(directory, progress_callback)
    # Keep only groups that actually have duplicates
    duplicate_groups = {
        file_hash: sorted(paths)
        for file_hash, paths in hash_dict.items()
        if len(paths) > 1
    }
    deleted_files = 0
    removed_folders = 0
    kept_files = 0
    delete_logs = []
    processed_groups = 0
    total_groups = len(duplicate_groups)

    for _, paths in duplicate_groups.items():
        processed_groups += 1

        # Keep the first sorted path, delete the rest
        keep_file = paths[0]
        duplicate_files = paths[1:]
        kept_files += 1

        delete_logs.append(f"Kept: {keep_file}")

        for dup_file in duplicate_files:
            try:
                os.remove(dup_file)
                deleted_files += 1
                msg = f"Deleted duplicate file: {dup_file}"
                delete_logs.append(msg)

                if progress_callback:
                    progress_callback(processed_groups, total_groups, msg)

            except Exception as e:
                err = f"Failed to delete duplicate -> {dup_file} ({e})"
                errors.append(err)
                delete_logs.append(err)

                if progress_callback:
                    progress_callback(processed_groups, total_groups, err)

    # Remove empty folders from bottom to top
    # Bottom-up traversal is important so child folders are removed first.
    for root, dirs, _ in os.walk(directory, topdown=False):
        for d in dirs:
            dir_path = os.path.join(root, d)
            try:
                if not os.listdir(dir_path):
                    os.rmdir(dir_path)
                    removed_folders += 1
                    delete_logs.append(f"Removed empty folder: {dir_path}")
            except Exception as e:
                errors.append(f"Failed to remove empty folder -> {dir_path} ({e})")

    return {
        "deleted_files": deleted_files,
        "removed_folders": removed_folders,
        "kept_files": kept_files,
        "duplicate_groups": total_groups,
        "logs": delete_logs,
        "errors": errors
    }


# =========================================================
# Main GUI application
# =========================================================
class FileOrganizerApp:
    """
    Main Tkinter application.

    This application contains two tabs:
    1. Organizer
       - Move/copy selected file types into category folders
    2. Duplicate Cleaner
       - Remove duplicate files by content hash and clean empty folders

    Threading model:
    - Long file operations run in worker threads
    - UI updates are sent back to the Tkinter main thread with root.after(...)
    - This avoids UI freezing and avoids unsafe direct cross-thread UI access
    """
    def __init__(self, root):
        self.root = root
        self.root.title("File Organizer")
        self.root.geometry("920x650")
        self.root.configure(bg="#FFD700")

        self.font = ('Arial', 12)
        self.font_color = "#3C0000"

        # Organizer tab paths
        self.source_directory = ""
        self.target_directory = ""

        # Duplicate cleaner tab path
        self.cleanup_directory = ""

        self.create_widgets()

    def create_widgets(self):
        """
        Build the notebook and both tabs.
        """
        style = ttk.Style()
        style.theme_use('default')

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.organize_tab = tk.Frame(self.notebook, bg="#FFD700")
        self.cleanup_tab = tk.Frame(self.notebook, bg="#FFD700")

        self.notebook.add(self.organize_tab, text="Organizer")
        self.notebook.add(self.cleanup_tab, text="Duplicate Cleaner")

        self.create_organize_tab()
        self.create_cleanup_tab()

    def create_organize_tab(self):
        """
        Create all widgets for the Organizer tab.
        """
        title_label = tk.Label(
            self.organize_tab,
            text="File Organizer",
            font=('Arial', 18, 'bold'),
            fg=self.font_color,
            bg="#FFD700"
        )
        title_label.pack(pady=15)

        self.source_button = tk.Button(
            self.organize_tab,
            text="Select Source Folder",
            font=self.font,
            fg=self.font_color,
            bg="#FFD700",
            command=self.choose_source_directory
        )
        self.source_button.pack(pady=8)

        self.target_button = tk.Button(
            self.organize_tab,
            text="Select Target Folder",
            font=self.font,
            fg=self.font_color,
            bg="#FFD700",
            command=self.choose_target_directory
        )
        self.target_button.pack(pady=8)

        self.move_button = tk.Button(
            self.organize_tab,
            text="Move Files",
            font=self.font,
            fg=self.font_color,
            bg="#FFD700",
            command=lambda: self.start_organize_worker(move=True)
        )
        self.move_button.pack(pady=8)

        self.copy_button = tk.Button(
            self.organize_tab,
            text="Copy Files",
            font=self.font,
            fg=self.font_color,
            bg="#FFD700",
            command=lambda: self.start_organize_worker(move=False)
        )
        self.copy_button.pack(pady=8)

        self.output_label = tk.Label(
            self.organize_tab,
            text="Please select a source folder and a target folder.",
            font=self.font,
            fg=self.font_color,
            bg="#FFD700",
            wraplength=840,
            justify="left"
        )
        self.output_label.pack(pady=12)

        self.log_text = tk.Text(
            self.organize_tab,
            height=18,
            width=108,
            font=('Consolas', 10)
        )
        self.log_text.pack(pady=10)

    def create_cleanup_tab(self):
        """
        Create all widgets for the Duplicate Cleaner tab.
        """
        title_label = tk.Label(
            self.cleanup_tab,
            text="Duplicate File Cleaner",
            font=('Arial', 18, 'bold'),
            fg=self.font_color,
            bg="#FFD700"
        )
        title_label.pack(pady=15)

        self.cleanup_choose_button = tk.Button(
            self.cleanup_tab,
            text="Select Folder to Clean",
            font=self.font,
            fg=self.font_color,
            bg="#FFD700",
            command=self.choose_cleanup_directory
        )
        self.cleanup_choose_button.pack(pady=8)

        self.cleanup_start_button = tk.Button(
            self.cleanup_tab,
            text="Delete Duplicate Files and Remove Empty Folders",
            font=self.font,
            fg=self.font_color,
            bg="#FFD700",
            command=self.start_cleanup_worker
        )
        self.cleanup_start_button.pack(pady=8)

        self.cleanup_output_label = tk.Label(
            self.cleanup_tab,
            text="Please select a folder for duplicate cleanup.",
            font=self.font,
            fg=self.font_color,
            bg="#FFD700",
            wraplength=840,
            justify="left"
        )
        self.cleanup_output_label.pack(pady=12)

        note_label = tk.Label(
            self.cleanup_tab,
            text=(
                "Rule: duplicate files are detected by content hash. "
                "One file is kept in each duplicate group, the extra copies are deleted, "
                "and empty folders are removed afterward."
            ),
            font=('Arial', 11),
            fg=self.font_color,
            bg="#FFD700",
            wraplength=840,
            justify="left"
        )
        note_label.pack(pady=4)

        self.cleanup_log_text = tk.Text(
            self.cleanup_tab,
            height=18,
            width=108,
            font=('Consolas', 10)
        )
        self.cleanup_log_text.pack(pady=10)

    # -----------------------------------------------------
    # Folder selection methods
    # -----------------------------------------------------
    def choose_source_directory(self):
        """
        Let the user select the source folder for file organization.
        """
        self.source_directory = filedialog.askdirectory(title="Select Source Folder")
        if self.source_directory:
            self.output_label.config(text=f"Source folder: {self.source_directory}")

    def choose_target_directory(self):
        """
        Let the user select the target folder for file organization.
        """
        self.target_directory = filedialog.askdirectory(title="Select Target Folder")
        if self.target_directory:
            self.output_label.config(text=f"Target folder: {self.target_directory}")

    def choose_cleanup_directory(self):
        """
        Let the user select the folder to scan for duplicates.
        """
        self.cleanup_directory = filedialog.askdirectory(title="Select Folder to Clean")
        if self.cleanup_directory:
            self.cleanup_output_label.config(text=f"Folder to clean: {self.cleanup_directory}")

    # -----------------------------------------------------
    # Button state helpers
    # -----------------------------------------------------
    def set_organize_buttons_state(self, state):
        """
        Enable or disable organizer tab buttons.
        """
        self.source_button.config(state=state)
        self.target_button.config(state=state)
        self.move_button.config(state=state)
        self.copy_button.config(state=state)

    def set_cleanup_buttons_state(self, state):
        """
        Enable or disable duplicate cleaner tab buttons.
        """
        self.cleanup_choose_button.config(state=state)
        self.cleanup_start_button.config(state=state)

    # -----------------------------------------------------
    # Log helpers
    # -----------------------------------------------------
    def append_log(self, message):
        """
        Append a line to the organizer log box.
        """
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def append_cleanup_log(self, message):
        """
        Append a line to the duplicate cleaner log box.
        """
        self.cleanup_log_text.insert(tk.END, message + "\n")
        self.cleanup_log_text.see(tk.END)

    # -----------------------------------------------------
    # Thread-safe UI update helpers
    # Tkinter should only be updated from the main thread.
    # root.after(0, ...) schedules the UI work safely.
    # -----------------------------------------------------
    def safe_set_status(self, text):
        self.root.after(0, lambda: self.output_label.config(text=text))

    def safe_append_log(self, text):
        self.root.after(0, lambda: self.append_log(text))

    def safe_set_cleanup_status(self, text):
        self.root.after(0, lambda: self.cleanup_output_label.config(text=text))

    def safe_append_cleanup_log(self, text):
        self.root.after(0, lambda: self.append_cleanup_log(text))

    def safe_show_info(self, title, message):
        self.root.after(0, lambda: messagebox.showinfo(title, message))

    def safe_show_error(self, title, message):
        self.root.after(0, lambda: messagebox.showerror(title, message))

    # -----------------------------------------------------
    # Organizer worker start
    # -----------------------------------------------------
    def start_organize_worker(self, move=True):
        """
        Validate organizer inputs and start the background thread.

        Why a thread is used:
        - File scanning and moving/copying may take a long time
        - Running those operations on the main UI thread would freeze the window
        """
        if not self.source_directory or not self.target_directory:
            messagebox.showerror("Error", "Please select both a source folder and a target folder first.")
            return

        source_abs = os.path.abspath(self.source_directory)
        target_abs = os.path.abspath(self.target_directory)

        if source_abs == target_abs:
            messagebox.showerror("Error", "Source and target folders cannot be the same.")
            return

        self.log_text.delete("1.0", tk.END)
        self.set_organize_buttons_state("disabled")

        threading.Thread(
            target=self.run_organize_task,
            args=(move,),
            daemon=True
        ).start()

    def run_organize_task(self, move=True):
        """
        Background worker for organizer operations.
        """
        try:
            action_text = "move" if move else "copy"
            self.safe_set_status(f"Scanning files and preparing to {action_text}...")

            categorized_files = scan_directory_for_files(
                self.source_directory,
                self.target_directory
            )

            total_files = sum(len(files) for files in categorized_files.values())

            if total_files == 0:
                self.safe_set_status("No files matched the allowed extension groups.")
                self.safe_show_info("Result", "No files matched the allowed extension groups.")
                self.root.after(0, lambda: self.set_organize_buttons_state("normal"))
                return

            def progress_callback(processed, total, result):
                self.safe_set_status(f"Processing: {processed}/{total}")
                self.safe_append_log(result)

            logs = process_files(
                categorized_files=categorized_files,
                target_directory=self.target_directory,
                move=move,
                progress_callback=progress_callback
            )
            success_count = sum(1 for x in logs if x.startswith("Moved:") or x.startswith("Copied:"))
            duplicate_count = sum(
                1 for x in logs
                if "Skipped duplicate content" in x or "Skipped same name / same content" in x
            )
            conflict_count = sum(1 for x in logs if "Conflict skipped" in x)
            fail_count = sum(1 for x in logs if x.startswith("Failed:"))
            summary = (
                f"{'Move' if move else 'Copy'} completed.\n"
                f"Successful: {success_count}\n"
                f"Duplicates skipped: {duplicate_count}\n"
                f"Conflicts skipped: {conflict_count}\n"
                f"Failed: {fail_count}"
            )
            self.safe_set_status(summary.replace("\n", " | "))
            self.safe_show_info("Result", summary)
        except Exception as e:
            self.safe_set_status("Operation failed.")
            self.safe_show_error("Error", f"An unexpected error occurred: {e}")
        finally:
            self.root.after(0, lambda: self.set_organize_buttons_state("normal"))
    # -----------------------------------------------------
    # Duplicate cleaner worker start
    # -----------------------------------------------------
    def start_cleanup_worker(self):
        """
        Validate duplicate cleaner input and start the background thread.
        """
        if not self.cleanup_directory:
            messagebox.showerror("Error", "Please select a folder to clean first.")
            return

        confirm = messagebox.askyesno(
            "Confirm Deletion",
            "The program will scan the selected folder, keep one file from each duplicate group, "
            "delete the extra duplicates, and remove empty folders.\n\nDo you want to continue?"
        )
        if not confirm:
            return

        self.cleanup_log_text.delete("1.0", tk.END)
        self.set_cleanup_buttons_state("disabled")

        threading.Thread(
            target=self.run_cleanup_task,
            daemon=True
        ).start()

    def run_cleanup_task(self):
        """
        Background worker for duplicate cleanup.
        """
        try:
            self.safe_set_cleanup_status("Scanning for duplicate files...")
            def progress_callback(current, total, result):
                if total > 0:
                    self.safe_set_cleanup_status(f"Working: {current}/{total}")
                else:
                    self.safe_set_cleanup_status("Working...")
                self.safe_append_cleanup_log(result)
            result = delete_duplicate_files(
                self.cleanup_directory,
                progress_callback=progress_callback
            )
            for log in result["logs"]:
                self.safe_append_cleanup_log(log)
            for err in result["errors"]:
                self.safe_append_cleanup_log(err)
            summary = (
                f"Duplicate cleanup completed.\n"
                f"Duplicate groups: {result['duplicate_groups']}\n"
                f"Files kept: {result['kept_files']}\n"
                f"Duplicate files deleted: {result['deleted_files']}\n"
                f"Empty folders removed: {result['removed_folders']}\n"
                f"Errors: {len(result['errors'])}"
            )
            self.safe_set_cleanup_status(summary.replace("\n", " | "))
            self.safe_show_info("Result", summary)
        except Exception as e:
            self.safe_set_cleanup_status("Cleanup failed.")
            self.safe_show_error("Error", f"An unexpected error occurred: {e}")
        finally:
            self.root.after(0, lambda: self.set_cleanup_buttons_state("normal"))
# =========================================================
# Application entry point
# =========================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = FileOrganizerApp(root)
    root.mainloop()
