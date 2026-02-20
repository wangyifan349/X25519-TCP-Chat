import os
import hashlib
import shutil
import threading
from collections import defaultdict
from pathlib import Path

# 文件扩展名，用于不同类型的文件
IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']  # 图片文件扩展名
VIDEO_EXTENSIONS = ['.mp4', '.mkv', '.avi', '.mov', '.flv', '.wmv']      # 视频文件扩展名
AUDIO_EXTENSIONS = ['.mp3', '.wav', '.flac', '.aac', '.ogg']            # 音频文件扩展名
OFFICE_EXTENSIONS = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']  # 文档文件扩展名（Office）
COMPRESSED_EXTENSIONS = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']   # 压缩文件扩展名

def calculate_file_hash(file_path):
    """计算文件的SHA-256哈希值，用于识别重复文件"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as file:
        # 以块为单位读取文件，避免内存过载
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def scan_directory_for_files(source_directory):
    """扫描目录并将文件分类"""
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
            elif file_extension in COMPRESSED_EXTENSIONS:
                categorized_files['compressed'].append(file_path)
    return categorized_files

def get_unique_filename(file_path, target_directory):
    """如果目标目录中已存在相同文件名，则生成唯一的文件名"""
    base_name = os.path.basename(file_path)
    new_name = base_name
    counter = 1
    while os.path.exists(os.path.join(target_directory, new_name)):
        name, extension = os.path.splitext(base_name)
        new_name = f"{name}_{counter}{extension}"
        counter += 1
    return new_name

def copy_or_move_file(file_path, target_directory, move=True):
    """根据用户的选择将文件复制或移动到目标目录"""
    new_name = get_unique_filename(file_path, target_directory)
    new_path = os.path.join(target_directory, new_name)
    if move:
        print(f"移动文件 {file_path} 到 {new_path}")
        shutil.move(file_path, new_path)
    else:
        print(f"复制文件 {file_path} 到 {new_path}")
        shutil.copy(file_path, new_path)

def move_or_copy_files(categorized_files, target_directory, move=True):
    """将文件移动或复制到目标目录"""
    for category, files in categorized_files.items():
        for file in files:
            # 调用函数将每个文件移动或复制到目标目录
            copy_or_move_file(file, target_directory, move)
def scan_directory_for_duplicates(target_directory):
    """扫描目标目录并根据文件哈希值查找重复文件"""
    hash_dict = defaultdict(list)
    for root, _, files in os.walk(target_directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_file_hash(file_path)
            hash_dict[file_hash].append(file_path)
    duplicates = {key: value for key, value in hash_dict.items() if len(value) > 1}
    return duplicates

def ask_user_to_delete_duplicates(duplicates):
    """提示用户删除重复文件"""
    if not duplicates:
        print("没有找到重复文件。")
        return
    for file_hash, files in duplicates.items():
        print(f"以下文件具有相同的哈希值：")
        for file in files:
            print(f"- {file}")
        answer = input("是否删除这些重复文件？(y/n): ")
        if answer.lower() == 'y':
            for file in files[1:]:  # 删除除了第一个文件之外的所有文件
                print(f"删除文件：{file}")
                os.remove(file)
def main():
    # Step 1: 扫描源目录并分类文件
    source_directory = input("请输入源目录路径: ")
    categorized_files = scan_directory_for_files(source_directory)
    # Step 2: 显示操作总结
    print("以下类型的文件将被处理：")
    for category, files in categorized_files.items():
        print(f"{category.capitalize()}: {len(files)} 个文件")
    # Step 3: 提示用户是否开始整理文件
    proceed = input("是否开始将文件整理到目标目录？(y/n): ")
    if proceed.lower() != 'y':
        print("操作已取消。")
        return
    # Step 4: 提示用户选择是复制还是移动文件
    action = input("选择操作：复制文件 (c) 还是移动文件 (m)：").strip().lower()
    if action == 'm':
        move_files = True
    elif action == 'c':
        move_files = False
    else:
        print("无效选择，操作已取消。")
        return
    # Step 5: 输入目标目录路径并开始移动或复制文件
    target_directory = input("请输入目标目录路径: ")
    # 使用线程来避免界面卡顿
    threading.Thread(target=move_or_copy_files, args=(categorized_files, target_directory, move_files), daemon=True).start()
    # Step 6: 扫描目标目录中的重复文件并提示用户删除
    duplicates = scan_directory_for_duplicates(target_directory)
    # Step 7: 提示用户是否删除重复文件
    ask_user_to_delete_duplicates(duplicates)
    print("操作完成。")

main()







import tkinter as tk
from tkinter import filedialog, messagebox
import os
import shutil
import hashlib
import threading
from collections import defaultdict

# 文件扩展名，用于不同类型的文件
IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']  # 图片文件扩展名
VIDEO_EXTENSIONS = ['.mp4', '.mkv', '.avi', '.mov', '.flv', '.wmv']      # 视频文件扩展名
AUDIO_EXTENSIONS = ['.mp3', '.wav', '.flac', '.aac', '.ogg']            # 音频文件扩展名
OFFICE_EXTENSIONS = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']  # 文档文件扩展名（Office）
COMPRESSED_EXTENSIONS = ['.zip', '.rar', '.7z', '.tar', '.gz']          # 压缩文件扩展名

def calculate_file_hash(file_path):
    """计算文件的SHA-256哈希值，用于识别重复文件"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as file:
        # 以块为单位读取文件，避免内存过载
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def scan_directory_for_files(source_directory):
    """扫描目录并将文件分类为图片、视频等"""
    categorized_files = defaultdict(list)
    # 遍历目录及其子目录
    for root, _, files in os.walk(source_directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_extension = os.path.splitext(file)[1].lower()
            # 根据扩展名将文件分类
            if file_extension in IMAGE_EXTENSIONS:
                categorized_files['images'].append(file_path)
            elif file_extension in VIDEO_EXTENSIONS:
                categorized_files['videos'].append(file_path)
            elif file_extension in AUDIO_EXTENSIONS:
                categorized_files['audio'].append(file_path)
            elif file_extension in OFFICE_EXTENSIONS:
                categorized_files['office'].append(file_path)
            elif file_extension in COMPRESSED_EXTENSIONS:
                categorized_files['compressed'].append(file_path)
    return categorized_files

def get_unique_filename(file_path, target_directory):
    """如果目标目录中已存在相同文件名，则生成唯一的文件名"""
    base_name = os.path.basename(file_path)
    new_name = base_name
    counter = 1
    while os.path.exists(os.path.join(target_directory, new_name)):
        # 添加数字后缀使文件名唯一
        name, extension = os.path.splitext(base_name)
        new_name = f"{name}_{counter}{extension}"
        counter += 1
    return new_name

def copy_or_move_file(file_path, target_directory, move=True):
    """根据用户的选择将文件复制或移动到目标目录"""
    new_name = get_unique_filename(file_path, target_directory)
    new_path = os.path.join(target_directory, new_name)
    
    if move:
        # 移动文件到新位置
        shutil.move(file_path, new_path)
    else:
        # 复制文件到新位置
        shutil.copy(file_path, new_path)

def move_or_copy_files(categorized_files, target_directory, move=True):
    """处理已分类的文件并将其移动或复制到目标目录"""
    for category, files in categorized_files.items():
        for file in files:
            # 调用函数将每个文件移动或复制到目标目录
            copy_or_move_file(file, target_directory, move)

def scan_directory_for_duplicates(target_directory):
    """扫描目标目录并根据文件哈希值查找重复文件"""
    hash_dict = defaultdict(list)
    # 遍历目标目录获取所有文件
    for root, _, files in os.walk(target_directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_file_hash(file_path)
            # 将哈希值作为键，文件路径作为值存储
            hash_dict[file_hash].append(file_path)
    
    # 找出重复文件（同一哈希值对应多个文件）
    duplicates = {key: value for key, value in hash_dict.items() if len(value) > 1}
    return duplicates

def ask_user_to_delete_duplicates(duplicates):
    """提示用户删除重复文件"""
    if not duplicates:
        return "没有找到重复文件。"
    
    for file_hash, files in duplicates.items():
        # 显示具有相同哈希值的文件
        response = messagebox.askyesno("删除重复文件", f"以下文件具有相同的哈希值：\n" + "\n".join(files) + "\n你想删除这些重复文件吗？")
        if response:
            for file in files[1:]:  # 删除除了第一个文件之外的所有文件
                os.remove(file)
            return "已删除重复文件。"
    return "操作已取消。"

class FileOrganizerApp:
    def __init__(self, root):
        """初始化GUI应用程序"""
        self.root = root
        self.root.title("文件组织器")
        self.root.geometry("600x400")  # 窗口大小
        self.root.configure(bg="#FFD700")  # 背景为金色

        # 字体和颜色设置
        self.font = ('Arial', 14)
        self.font_color = "#3C0000"  # RGB 60, 0, 0

        # 源目录和目标目录变量
        self.source_directory = ""
        self.target_directory = ""

        self.create_widgets()

    def create_widgets(self):
        """创建并显示界面组件（按钮、标签）"""
        # 标题标签
        title_label = tk.Label(self.root, text="文件组织器", font=('Arial', 18, 'bold'), fg=self.font_color, bg="#FFD700")
        title_label.pack(pady=20)

        # 源目录选择按钮
        self.source_button = tk.Button(self.root, text="选择源目录", font=self.font, fg=self.font_color, bg="#FFD700", command=self.choose_source_directory)
        self.source_button.pack(pady=10)

        # 目标目录选择按钮
        self.target_button = tk.Button(self.root, text="选择目标目录", font=self.font, fg=self.font_color, bg="#FFD700", command=self.choose_target_directory)
        self.target_button.pack(pady=10)

        # 移动文件按钮
        self.move_button = tk.Button(self.root, text="移动文件", font=self.font, fg=self.font_color, bg="#FFD700", command=self.start_move_files_thread)
        self.move_button.pack(pady=10)

        # 复制文件按钮
        self.copy_button = tk.Button(self.root, text="复制文件", font=self.font, fg=self.font_color, bg="#FFD700", command=self.start_copy_files_thread)
        self.copy_button.pack(pady=10)

        # 输出标签
        self.output_label = tk.Label(self.root, text="选择目录并开始整理文件。", font=self.font, fg=self.font_color, bg="#FFD700")
        self.output_label.pack(pady=20)

    def choose_source_directory(self):
        """打开对话框选择源目录"""
        self.source_directory = filedialog.askdirectory(title="选择源目录")
        if self.source_directory:
            self.output_label.config(text=f"源目录：{self.source_directory}")

    def choose_target_directory(self):
        """打开对话框选择目标目录"""
        self.target_directory = filedialog.askdirectory(title="选择目标目录")
        if self.target_directory:
            self.output_label.config(text=f"目标目录：{self.target_directory}")

    def start_move_files_thread(self):
        """在独立线程中启动文件移动操作"""
        if not self.source_directory or not self.target_directory:
            messagebox.showerror("错误", "请先选择源目录和目标目录。")
            return
        # 启动一个新的线程来处理文件移动
        threading.Thread(target=self.move_files, daemon=True).start()

    def start_copy_files_thread(self):
        """在独立线程中启动文件复制操作"""
        if not self.source_directory or not self.target_directory:
            messagebox.showerror("错误", "请先选择源目录和目标目录。")
            return
        # 启动一个新的线程来处理文件复制
        threading.Thread(target=self.copy_files, daemon=True).start()

    def move_files(self):
        """将文件从源目录移动到目标目录"""
        # 扫描并分类文件
        categorized_files = scan_directory_for_files(self.source_directory)

        # 移动或复制文件
        move_or_copy_files(categorized_files, self.target_directory, move=True)

        # 检查重复文件并提示用户
        duplicates = scan_directory_for_duplicates(self.target_directory)
        result = ask_user_to_delete_duplicates(duplicates)
        messagebox.showinfo("结果", result)

    def copy_files(self):
        """将文件从源目录复制到目标目录"""
        # 扫描并分类文件
        categorized_files = scan_directory_for_files(self.source_directory)

        # 移动或复制文件
        move_or_copy_files(categorized_files, self.target_directory, move=False)

        # 检查重复文件并提示用户
        duplicates = scan_directory_for_duplicates(self.target_directory)
        result = ask_user_to_delete_duplicates(duplicates)
        messagebox.showinfo("结果", result)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileOrganizerApp(root)
    root.mainloop()
