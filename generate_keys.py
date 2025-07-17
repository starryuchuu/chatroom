from Crypto.PublicKey import RSA

# 生成2048位的RSA密钥对
key = RSA.generate(2048)

# 导出私钥并保存到文件
private_key = key.export_key()
with open('private_key.pem', 'wb') as f:
    f.write(private_key)

# 导出公钥并保存到文件
public_key = key.publickey().export_key()
with open('public_key.pem', 'wb') as f:
    f.write(public_key)

print("RSA密钥对 'private_key.pem' 和 'public_key.pem' 已成功生成。")
