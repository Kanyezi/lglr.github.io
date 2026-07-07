import os
import re
import ast

def read_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        return f.read()
    
def jiexi(content):
    # 在这里添加解析逻辑
    # 正则表达式为 \[\s*(?:\d+|"[^"]*")\s*(?:,\s*(?:\d+|"[^"]*")\s*){9},\s*4\s*(?:,\s*(?:\d+|"[^"]*")\s*)*\]

    zhenze = r'\[\s*(?:\d+|"(?:[^"\\]|\\.)*")\s*(?:,\s*(?:\d+|"(?:[^"\\]|\\.)*")\s*){9},\s*4\s*(?:,\s*(?:\d+|"(?:[^"\\]|\\.)*")\s*)*\]'

    r = re.findall(zhenze, content)

    #特殊名字替换
    # 正则匹配：前缀 + 数字 + 后缀
    pattern = r'\{\[B_SP_\]\}Locale#mpn#0\{\[B_SP_\]\}(\d+)\{\[E_SP_\]\}\{\[E_SP_\]\}'
    replacement = r'开拓者\1'

    for i in range(len(r)):
        r[i] = re.sub(pattern, replacement, r[i])

        # 2. 【新增】去除数字前导零（保留单独的 0）
        #    匹配逗号或左括号后面的 0+数字，替换为去掉前导零的数字
        r[i] = re.sub(r'(?<=[,\[])\s*0+(\d+)', r'\1', r[i])
        
        if(len(ast.literal_eval(r[i])) != 48):
            print(f"Skipping item with unexpected length: {r[i]}")

    return r;


def save(items, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        for item in items:
            f.write(str(item) + '\n')

def main():
    #遍历.\decoded_messages文件夹下S_开头的文件
    all_items = []
    for filename in os.listdir('.\decoded_messages'):
        if filename.startswith('S_'):
            content = read_file(f'.\decoded_messages\{filename}')
            cts = jiexi(content)
            print(f"Matches in {filename}:")
            for c in cts:
                try:
                    arr = ast.literal_eval(c)   # 安全解析为 Python list
                    all_items.append(arr)
                except:
                    print(f"跳过无法解析的片段：{c[:50]}...")
    unique = list(set(tuple(arr) for arr in all_items))
    print(f"Unique matches: {len(unique)}")
    save(unique, "unique_matches.json")
if __name__ == "__main__":
    main()