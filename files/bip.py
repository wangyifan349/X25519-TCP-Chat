import sys
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator
from bip_utils import Bip32, Bip32Path
from bip_utils import Bip39MnemonicValidator, Bech32Encoder
import os


# 创建比特币钱包（BIP84）
def create_bitcoin_wallet():
    print("正在生成一个安全的 24 个单词的比特币钱包（BIP84）...")
    
    # 生成24个单词的助记词（更高安全性）
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(24)
    print(f"生成的助记词: {mnemonic}")
    
    # 从助记词生成种子
    seed = Bip39SeedGenerator(mnemonic).Generate()
    print(f"生成的种子: {seed.hex()}")
    
    # 使用种子生成BIP32根密钥
    bip32 = Bip32.FromSeed(seed)
    
    # 使用BIP84路径派生比特币钱包的私钥（Bech32地址）
    bip32_path = Bip32Path("m/84'/0'/0'/0/0")  # BIP84路径
    private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
    
    # 从私钥生成Bech32地址
    public_key = bip32.DerivePath(bip32_path).PublicKey().ToAddress()
    
    print(f"钱包私钥: {private_key}")
    print(f"比特币 Bech32 地址: {public_key}")
    
    # 安全建议：打印贴纸
    print("\n-------------------- 安全建议 --------------------")
    print("1. 请妥善保存助记词（24个单词）。")
    print("2. 不要将助记词保存在电子设备上，最好将其纸质记录。")
    print("3. 请将助记词存放在安全的位置，避免遗失或被盗。")
    print("4. 不要与任何人分享你的助记词或私钥！")
    print("5. 可以将助记词打印到纸张上并封存，不要随便存放或拍照。")
    print("----------------------------------------------------")


# 创建Zcash钱包（BIP44）
def create_zcash_wallet():
    print("正在生成一个安全的 24 个单词的Zcash钱包（BIP44）...")
    
    # 生成24个单词的助记词（更高安全性）
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(24)
    print(f"生成的助记词: {mnemonic}")
    
    # 从助记词生成种子
    seed = Bip39SeedGenerator(mnemonic).Generate()
    print(f"生成的种子: {seed.hex()}")
    
    # 使用种子生成BIP32根密钥
    bip32 = Bip32.FromSeed(seed)
    
    # 使用BIP44路径派生Zcash钱包的私钥
    bip32_path = Bip32Path("m/44'/133'/0'/0/0")  # Zcash的BIP44路径
    private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
    
    # 从私钥生成Zcash地址
    public_key = bip32.DerivePath(bip32_path).PublicKey().ToAddress()
    
    print(f"钱包私钥: {private_key}")
    print(f"Zcash 地址: {public_key}")
    
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
        
        # 询问用户选择币种
        coin_type = input("请选择币种（1: 比特币，2: Zcash）：")
        
        if coin_type == '1':
            # 生成比特币钱包（BIP84）
            bip32 = Bip32.FromSeed(seed)
            bip32_path = Bip32Path("m/84'/0'/0'/0/0")  # BIP84路径
            private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
            public_key = bip32.DerivePath(bip32_path).PublicKey().ToAddress()
            print(f"比特币私钥: {private_key}")
            print(f"比特币 Bech32 地址: {public_key}")
        elif coin_type == '2':
            # 生成Zcash钱包（BIP44）
            bip32 = Bip32.FromSeed(seed)
            bip32_path = Bip32Path("m/44'/133'/0'/0/0")  # Zcash的BIP44路径
            private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
            public_key = bip32.DerivePath(bip32_path).PublicKey().ToAddress()
            print(f"Zcash私钥: {private_key}")
            print(f"Zcash 地址: {public_key}")
        else:
            print("无效选择！")

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
        
        # 询问用户选择币种
        coin_type = input("请选择币种（1: 比特币，2: Zcash）：")
        
        if coin_type == '1':
            # 查看比特币钱包信息（BIP84）
            bip32 = Bip32.FromSeed(seed)
            bip32_path = Bip32Path("m/84'/0'/0'/0/0")  # BIP84路径
            private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
            public_key = bip32.DerivePath(bip32_path).PublicKey().ToAddress()
            print(f"比特币私钥: {private_key}")
            print(f"比特币 Bech32 地址: {public_key}")
        elif coin_type == '2':
            # 查看Zcash钱包信息（BIP44）
            bip32 = Bip32.FromSeed(seed)
            bip32_path = Bip32Path("m/44'/133'/0'/0/0")  # Zcash的BIP44路径
            private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
            public_key = bip32.DerivePath(bip32_path).PublicKey().ToAddress()
            print(f"Zcash私钥: {private_key}")
            print(f"Zcash 地址: {public_key}")
        else:
            print("无效选择！")
        
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
        print("1. 创建比特币钱包 (BIP84)")
        print("2. 创建Zcash钱包 (BIP44)")
        print("3. 导入钱包")
        print("4. 查看钱包信息")
        print("5. 退出")
        
        choice = input("请输入选项 (1/2/3/4/5): ")

        if choice == '1':
            create_bitcoin_wallet()
        elif choice == '2':
            create_zcash_wallet()
        elif choice == '3':
            import_wallet()
        elif choice == '4':
            view_wallet_info()
        elif choice == '5':
            print("退出程序")
            sys.exit()
        else:
            print("无效的选项，请重新选择!")


# 运行程序
if __name__ == "__main__":
    show_menu()
