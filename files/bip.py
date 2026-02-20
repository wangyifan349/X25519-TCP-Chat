import sys
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator
from bip_utils import Bip32, Bip32Path
from bip_utils import Bip39MnemonicValidator
import os


# 创建钱包（使用24个单词助记词）
def create_wallet():
    print("正在生成一个安全的 24 个单词的助记词...")
    
    # 使用24个单词的助记词来增强安全性
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(24)
    print(f"生成的助记词: {mnemonic}")
    
    # 从助记词生成种子
    seed = Bip39SeedGenerator(mnemonic).Generate()
    print(f"生成的种子: {seed.hex()}")
    
    # 使用种子生成BIP32根密钥
    bip32 = Bip32.FromSeed(seed)
    
    # 通过BIP44路径派生一个私钥
    bip32_path = Bip32Path("m/44'/0'/0'/0/0")  # 示例路径
    private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
    print(f"钱包私钥: {private_key}")

    # 安全建议：打印贴纸
    print("\n-------------------- 安全建议 --------------------")
    print("1. 请妥善保存助记词（24个单词）。")
    print("2. 不要将助记词保存在电子设备上，最好将其纸质记录。")
    print("3. 请将助记词存放在安全的位置，避免遗失或被盗。")
    print("4. 不要与任何人分享你的助记词或私钥！")
    print("5. 可以将助记词打印到纸张上并封存，不要随便存放或拍照。")
    print("----------------------------------------------------")

# 导入钱包（通过24个单词的助记词）
def import_wallet():
    mnemonic = input("请输入24个单词的助记词：")
    
    try:
        # 验证助记词是否有效
        Bip39MnemonicValidator(mnemonic).Validate()
        print("助记词有效，正在生成种子...")
        
        # 从助记词生成种子
        seed = Bip39SeedGenerator(mnemonic).Generate()
        print(f"生成的种子: {seed.hex()}")
        
        # 使用种子生成BIP32根密钥
        bip32 = Bip32.FromSeed(seed)
        
        # 通过BIP44路径派生一个私钥
        bip32_path = Bip32Path("m/44'/0'/0'/0/0")  # 示例路径
        private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
        print(f"导入的钱包私钥: {private_key}")
        
        # 安全建议：打印贴纸
        print("\n-------------------- 安全建议 --------------------")
        print("1. 请妥善保存助记词（24个单词）。")
        print("2. 不要将助记词保存在电子设备上，最好将其纸质记录。")
        print("3. 请将助记词存放在安全的位置，避免遗失或被盗。")
        print("4. 不要与任何人分享你的助记词或私钥！")
        print("5. 可以将助记词打印到纸张上并封存，不要随便存放或拍照。")
        print("----------------------------------------------------")
    except Exception as e:
        print(f"错误: {e}")


# 查看钱包信息（需要输入24个单词的助记词）
def view_wallet_info():
    mnemonic = input("请输入24个单词的助记词以查看钱包信息：")
    
    try:
        # 验证助记词是否有效
        Bip39MnemonicValidator(mnemonic).Validate()
        print("助记词有效，正在显示钱包信息...")
        
        # 从助记词生成种子
        seed = Bip39SeedGenerator(mnemonic).Generate()
        
        # 使用种子生成BIP32根密钥
        bip32 = Bip32.FromSeed(seed)
        
        # 通过BIP44路径派生一个私钥
        bip32_path = Bip32Path("m/44'/0'/0'/0/0")  # 示例路径
        private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
        
        print(f"钱包信息:\n私钥: {private_key}\n种子: {seed.hex()}")
        
        # 安全建议：打印贴纸
        print("\n-------------------- 安全建议 --------------------")
        print("1. 请妥善保存助记词（24个单词）。")
        print("2. 不要将助记词保存在电子设备上，最好将其纸质记录。")
        print("3. 请将助记词存放在安全的位置，避免遗失或被盗。")
        print("4. 不要与任何人分享你的助记词或私钥！")
        print("5. 可以将助记词打印到纸张上并封存，不要随便存放或拍照。")
        print("----------------------------------------------------")
    except Exception as e:
        print(f"错误: {e}")


# 显示主菜单
def show_menu():
    while True:
        print("\n欢迎使用钱包管理系统！请选择一个操作:")
        print("1. 创建新钱包")
        print("2. 导入钱包")
        print("3. 查看钱包信息")
        print("4. 退出")
        
        choice = input("请输入选项 (1/2/3/4): ")

        if choice == '1':
            create_wallet()
        elif choice == '2':
            import_wallet()
        elif choice == '3':
            view_wallet_info()
        elif choice == '4':
            print("退出程序")
            sys.exit()
        else:
            print("无效的选项，请重新选择!")


# 运行程序
if __name__ == "__main__":
    show_menu()
