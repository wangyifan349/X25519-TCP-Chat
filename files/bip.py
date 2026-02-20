import sys
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator
from bip_utils import Bip32, Bip32Path, Bip44, Bip44Coins, Bip84
from bip_utils import Bip39MnemonicValidator, Bech32Encoder
import os


# Create a Bitcoin wallet (BIP84)
def create_bitcoin_wallet():
    print("Generating a secure Bitcoin wallet with 24 words (BIP84)...")
    
    # Generate 24-word mnemonic for higher security
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(24)
    print(f"Generated Mnemonic: {mnemonic}")
    
    # Generate seed from the mnemonic
    seed = Bip39SeedGenerator(mnemonic).Generate()
    print(f"Generated Seed: {seed.hex()}")
    
    # Generate BIP32 root key from the seed
    bip32 = Bip32.FromSeed(seed)
    
    # Derive the Bitcoin wallet private key using BIP84 path (Bech32 address)
    bip32_path = Bip32Path("m/84'/0'/0'/0/0")  # BIP84 path
    private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
    
    # Generate Bech32 address from the private key
    public_key = bip32.DerivePath(bip32_path).PublicKey().ToAddress()
    
    print(f"Wallet Private Key: {private_key}")
    print(f"Bitcoin Bech32 Address: {public_key}")
    
    # Security advice
    print("\n-------------------- Security Advice --------------------")
    print("1. Safeguard your mnemonic (24 words).")
    print("2. Do not store your mnemonic on electronic devices; write it on paper.")
    print("3. Keep your mnemonic in a safe location to avoid loss or theft.")
    print("4. Do not share your mnemonic or private key with anyone!")
    print("5. You can print your mnemonic on paper and store it safely; avoid taking pictures.")
    print("--------------------------------------------------------")


# Create a Zcash wallet (BIP44)
def create_zcash_wallet():
    print("Generating a secure Zcash wallet with 24 words (BIP44)...")
    
    # Generate 24-word mnemonic for higher security
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(24)
    print(f"Generated Mnemonic: {mnemonic}")
    
    # Generate seed from the mnemonic
    seed = Bip39SeedGenerator(mnemonic).Generate()
    print(f"Generated Seed: {seed.hex()}")
    
    # Generate BIP32 root key from the seed
    bip32 = Bip32.FromSeed(seed)
    
    # Derive the Zcash wallet private key using BIP44 path
    bip32_path = Bip32Path("m/44'/133'/0'/0/0")  # Zcash BIP44 path
    private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
    
    # Generate Zcash address from the private key
    public_key = bip32.DerivePath(bip32_path).PublicKey().ToAddress()
    
    print(f"Wallet Private Key: {private_key}")
    print(f"Zcash Address: {public_key}")
    
    # Security advice
    print("\n-------------------- Security Advice --------------------")
    print("1. Safeguard your mnemonic (24 words).")
    print("2. Do not store your mnemonic on electronic devices; write it on paper.")
    print("3. Keep your mnemonic in a safe location to avoid loss or theft.")
    print("4. Do not share your mnemonic or private key with anyone!")
    print("5. You can print your mnemonic on paper and store it safely; avoid taking pictures.")
    print("--------------------------------------------------------")


# Import wallet (using 24-word mnemonic)
def import_wallet():
    mnemonic = input("Enter your 24-word mnemonic: ")
    
    try:
        # Validate if the mnemonic is valid
        Bip39MnemonicValidator(mnemonic).Validate()
        print("Mnemonic is valid, generating seed...")
        
        # Generate seed from the mnemonic
        seed = Bip39SeedGenerator(mnemonic).Generate()
        print(f"Generated Seed: {seed.hex()}")
        
        # Ask the user to select the coin type
        coin_type = input("Select the coin type (1: Bitcoin, 2: Zcash): ")
        
        if coin_type == '1':
            # Generate Bitcoin wallet (BIP84)
            bip32 = Bip32.FromSeed(seed)
            bip32_path = Bip32Path("m/84'/0'/0'/0/0")  # BIP84 path
            private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
            public_key = bip32.DerivePath(bip32_path).PublicKey().ToAddress()
            print(f"Bitcoin Private Key: {private_key}")
            print(f"Bitcoin Bech32 Address: {public_key}")
        elif coin_type == '2':
            # Generate Zcash wallet (BIP44)
            bip32 = Bip32.FromSeed(seed)
            bip32_path = Bip32Path("m/44'/133'/0'/0/0")  # Zcash BIP44 path
            private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
            public_key = bip32.DerivePath(bip32_path).PublicKey().ToAddress()
            print(f"Zcash Private Key: {private_key}")
            print(f"Zcash Address: {public_key}")
        else:
            print("Invalid selection!")

    except Exception as e:
        print(f"Error: {e}")


# View wallet information (requires 24-word mnemonic)
def view_wallet_info():
    mnemonic = input("Enter your 24-word mnemonic to view wallet info: ")
    
    try:
        # Validate if the mnemonic is valid
        Bip39MnemonicValidator(mnemonic).Validate()
        print("Mnemonic is valid, displaying wallet information...")
        
        # Generate seed from the mnemonic
        seed = Bip39SeedGenerator(mnemonic).Generate()
        
        # Ask the user to select the coin type
        coin_type = input("Select the coin type (1: Bitcoin, 2: Zcash): ")
        
        if coin_type == '1':
            # View Bitcoin wallet info (BIP84)
            bip32 = Bip32.FromSeed(seed)
            bip32_path = Bip32Path("m/84'/0'/0'/0/0")  # BIP84 path
            private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
            public_key = bip32.DerivePath(bip32_path).PublicKey().ToAddress()
            print(f"Bitcoin Private Key: {private_key}")
            print(f"Bitcoin Bech32 Address: {public_key}")
        elif coin_type == '2':
            # View Zcash wallet info (BIP44)
            bip32 = Bip32.FromSeed(seed)
            bip32_path = Bip32Path("m/44'/133'/0'/0/0")  # Zcash BIP44 path
            private_key = bip32.DerivePath(bip32_path).PrivateKey().ToHex()
            public_key = bip32.DerivePath(bip32_path).PublicKey().ToAddress()
            print(f"Zcash Private Key: {private_key}")
            print(f"Zcash Address: {public_key}")
        else:
            print("Invalid selection!")
        
        # Security advice
        print("\n-------------------- Security Advice --------------------")
        print("1. Safeguard your mnemonic (24 words).")
        print("2. Do not store your mnemonic on electronic devices; write it on paper.")
        print("3. Keep your mnemonic in a safe location to avoid loss or theft.")
        print("4. Do not share your mnemonic or private key with anyone!")
        print("5. You can print your mnemonic on paper and store it safely; avoid taking pictures.")
        print("--------------------------------------------------------")
    except Exception as e:
        print(f"Error: {e}")


# Show main menu
def show_menu():
    while True:
        print("\nWelcome to the Wallet Management System! Please select an operation:")
        print("1. Create Bitcoin Wallet (BIP84)")
        print("2. Create Zcash Wallet (BIP44)")
        print("3. Import Wallet")
        print("4. View Wallet Information")
        print("5. Exit")
        
        choice = input("Enter your choice (1/2/3/4/5): ")

        if choice == '1':
            create_bitcoin_wallet()
        elif choice == '2':
            create_zcash_wallet()
        elif choice == '3':
            import_wallet()
        elif choice == '4':
            view_wallet_info()
        elif choice == '5':
            print("Exiting the program")
            sys.exit()
        else:
            print("Invalid option, please try again!")


# Run the program
if __name__ == "__main__":
    show_menu()




from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip32, Bip44, Bip44Coins, Bip84
from bip_utils import Bip39MnemonicValidator

# 1. Generate a 24-word mnemonic
mnemonic = Bip39MnemonicGenerator().Generate(strength=256)  # Strength 256 for 24 words
print(f"Generated Mnemonic: {mnemonic}")

# 2. Validate the mnemonic
is_valid = Bip39MnemonicValidator().IsValid(mnemonic)
print(f"Mnemonic is valid: {is_valid}")

# 3. Generate a seed from the mnemonic
seed = Bip39SeedGenerator(mnemonic).Generate()
print(f"Generated Seed: {seed.hex()}")

# 4. Use BIP32 to generate the root key from the seed
bip32 = Bip32.FromSeed(seed)

# 5. Derive the first child key (m/0/0)
child_key = bip32.DerivePath("m/0/0")
print(f"Derived child private key: {child_key.PrivateKey().ToHex()}")
print(f"Derived child public key: {child_key.PublicKey().ToHex()}")

# 6. Use BIP44 to derive the Bitcoin address (m/44'/0'/0'/0/0)
bip44 = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
address = bip44.Purpose().Coin().Account(0).Change(0).Address(0).ToAddress()
print(f"BIP44 derived Bitcoin address: {address}")

# 7. Use BIP84 to derive the Bitcoin SegWit address (m/84'/0'/0'/0/0)
bip84 = Bip84.FromSeed(seed, Bip44Coins.BITCOIN)
segwit_address = bip84.Purpose().Coin().Account(0).Change(0).Address(0).ToAddress()
print(f"BIP84 derived Bitcoin SegWit address: {segwit_address}")

# Extra: Derive keys at other levels, e.g., m/44'/0'/0'/0/1 or m/84'/0'/0'/0/1
address_1 = bip84.Purpose().Coin().Account(0).Change(0).Address(1).ToAddress()
print(f"BIP84 derived second Bitcoin SegWit address: {address_1}")
