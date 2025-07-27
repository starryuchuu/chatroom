import sqlite3

# 连接到数据库
conn = sqlite3.connect('chat.db')
cursor = conn.cursor()

# 获取所有表名
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()

print("数据库中的表:")
for table in tables:
    print(f"- {table[0]}")

# 查看groups表结构
print("\ngroups表结构:")
cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='groups'")
result = cursor.fetchone()
if result:
    print(result[0])
else:
    print("groups表不存在")

# 查看groups表中的数据
print("\ngroups表数据:")
try:
    cursor.execute("SELECT * FROM groups")
    rows = cursor.fetchall()
    if rows:
        for row in rows:
            print(row)
    else:
        print("groups表为空")
except sqlite3.OperationalError as e:
    print(f"查询groups表时出错: {e}")

conn.close()
