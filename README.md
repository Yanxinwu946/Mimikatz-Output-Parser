# Mimikatz Output Parser

## Overview
A Python tool to parse Mimikatz output files and extract user credentials, including NTLM hashes, in a clean and organized format.

## Features
- Extracts user credentials (username, domain, NTLM hash) from Mimikatz output
- Supports both authentication blocks and SAM dump sections
- Outputs in two formats:
  - Formatted text table with dynamic column widths
  - Hashcat-compatible format for password cracking
- Optional colorized output for better readability
- Unique hash filtering for hashcat output
- Output to stdout or file

### Options
- `-o, --output <file>`: Save output to a file (default: stdout)
- `-f, --format <text|hashcat>`: Output format (default: text)
- `-u, --unique`: Output only unique hashes (hashcat format only)
- `-c, --color`: Enable colorized output (text format only, terminal only)

### Examples
1. Parse a file and display a formatted table:
```bash
python parse_mimikatz.py mimikatz_output.txt
```

2. Parse with colorized output:
```bash
python parse_mimikatz.py mimikatz_output.txt -c
```

3. Output in hashcat format to a file:
```bash
python parse_mimikatz.py mimikatz_output.txt -f hashcat -o hashes.txt
```

4. Output unique hashes only in hashcat format:
```bash
python parse_mimikatz.py mimikatz_output.txt -f hashcat -u
```

## Output Examples
### Text Format
```
Username        Domain        NTLM Hash
============================================================
jdoe            CORP          aad3b435b51404eeaad3b435b51404ee
admin           CORP          31d6cfe0d16ae931b73c59d7e0c089c0
```

### Hashcat Format
```
aad3b435b51404eeaad3b435b51404ee:CORP\jdoe
31d6cfe0d16ae931b73c59d7e0c089c0:CORP\admin
```

## Contributing
Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -am 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Create a Pull Request

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer
This tool is intended for security researchers and penetration testers with proper authorization. Use responsibly and only on systems you have permission to test. The author is not responsible for any misuse or damage caused by this tool.

---

# Mimikatz 输出解析器

## 概述
一个用于解析 Mimikatz 输出文件的 Python 工具，以清晰且有组织的格式提取用户凭据，包括 NTLM 哈希。

## 功能
- 从 Mimikatz 输出中提取用户凭据（用户名、域名、NTLM 哈希）
- 支持解析认证块和 SAM 转储部分
- 支持两种输出格式：
  - 动态列宽的格式化文本表格
  - 兼容 Hashcat 的格式，用于密码破解
- 可选的彩色输出，提升可读性
- 支持 Hashcat 格式的唯一哈希过滤
- 支持输出到标准输出或文件

### 选项
- `-o, --output <文件>`：将输出保存到文件（默认：标准输出）
- `-f, --format <text|hashcat>`：输出格式（默认：text）
- `-u, --unique`：仅输出唯一哈希（仅限 hashcat 格式）
- `-c, --color`：启用彩色输出（仅限 text 格式，仅限终端）

### 示例
1. 解析文件并显示格式化表格：
```bash
python parse_mimikatz.py mimikatz_output.txt
```

2. 使用彩色输出解析：
```bash
python parse_mimikatz.py mimikatz_output.txt -c
```

3. 以 hashcat 格式输出到文件：
```bash
python parse_mimikatz.py mimikatz_output.txt -f hashcat -o hashes.txt
```

4. 仅输出 hashcat 格式的唯一哈希：
```bash
python parse_mimikatz.py mimikatz_output.txt -f hashcat -u
```

## 输出示例
### 文本格式
```
用户名          域名          NTLM 哈希
============================================================
jdoe            CORP          aad3b435b51404eeaad3b435b51404ee
admin           CORP          31d6cfe0d16ae931b73c59d7e0c089c0
```

### Hashcat 格式
```
aad3b435b51404eeaad3b435b51404ee:CORP\jdoe
31d6cfe0d16ae931b73c59d7e0c089c0:CORP\admin
```

## 贡献
欢迎贡献！请按照以下步骤操作：
1. fork仓库
2. 创建功能分支（`git checkout -b feature/your-feature`）
3. 提交更改（`git commit -am 'Add your feature'`）
4. 推送分支（`git push origin feature/your-feature`）
5. 创建拉取请求

## 许可证
本项目采用 MIT 许可证授权。详情请见 [LICENSE](LICENSE) 文件。

## 免责声明
此工具仅限具有适当授权的安全研究人员和渗透测试人员使用。请负责任地使用，仅在您有权限测试的系统上使用。作者对任何滥用或由此工具造成的损害不承担责任。
