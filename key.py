from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os

# 生成新的密钥对
key = RSA.generate(2048)

# 保存私钥到文件
with open('private_key.pem', 'wb') as f:
    f.write(key.export_key())

# 保存公钥到文件
with open('public_key.pem', 'wb') as f:
    f.write(key.publickey().export_key())

print("密钥对已生成并保存到文件。")
