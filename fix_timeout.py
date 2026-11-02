import os

for root, dirs, files in os.walk('.'):
    for file in files:
        if file.endswith('.py'):
            filepath = os.path.join(root, file)
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if 'timeout=30' in content:
                new_content = content.replace('timeout=30', 'timeout=30')
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f"[+] Updated timeout in: {filepath}")
