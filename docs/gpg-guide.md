# GPG 使用指南（配合本项目）

## 先回答最常见的问题：`.gpg` 与 `.asc` 是什么关系？

它们**不是两种加密格式，而是同一 OpenPGP 数据的两种存放形式**，后缀只是约定：

| 后缀 | 内容形式 | 特点 |
|---|---|---|
| `.gpg` | **二进制** OpenPGP 报文 | 体积小 ~33%，适合文件传输 |
| `.asc` | **ASCII Armor**（base64 文本，带 `-----BEGIN...-----` 头尾） | 文本安全：可复制粘贴、进邮件、进聊天、不会被编码损坏 |

关键点：

1. **`.asc` 不是"公钥专用格式"**——公钥、私钥、加密报文、签名，任何 OpenPGP 对象都可以放 Armor 里。
   你看到 `.asc` 常出现在公钥上，只是因为公钥常需要文本形式分享（密钥服务器、邮件正文）。
2. 加密内容本身完全一样：`a.gpg` 与 `a.asc` 互转不损失任何信息：
   ```bash
   gpg --enarmor < a.gpg > a.asc   # 二进制 → 文本
   gpg --dearmor < a.asc > a.gpg   # 文本 → 二进制
   ```
3. `gpg --decrypt` 两种后缀通吃，无需任何参数区分。

**本项目为什么输出 `.asc`**：命中产物（助记词+地址等敏感明文的密文）选择文本形式，
便于在网页、邮件、剪贴板之间安全流转且可肉眼校验头尾完整性
（`-----BEGIN PGP MESSAGE-----` … `-----END PGP MESSAGE-----`）。

## 最小上手流程（5 条命令）

```bash
# 1. 生成自己的密钥（交互式；只管加密用选默认即可）
gpg --full-generate-key

# 2. 导出公钥（armor 文本）→ 交给本工具：写入 config 的 gpg_key_inline，
#    或存成 fx1024.asc 同类文件 / 演示工作流的 gpg Secret
gpg --armor --export 你的邮箱 > mypubkey.asc

# 3. （工具产出的密文在别人机器上）导入公钥的那台机器需要的是——
#    其实解密只需要你这台机器上有私钥（~/.gnupg 自动管理）
gpg --list-secret-keys    # 确认私钥在

# 4. 解密工具产物
gpg --decrypt vanity_20260926_172316_001.asc > wallet.txt

# 5. 校验公钥指纹（把别人给你的公钥核对一遍再使用）
gpg --show-keys --with-fingerprint mypubkey.asc
```

## 常用速查

```bash
gpg --list-keys                        # 列出公钥
gpg --import mypubkey.asc              # 导入公钥
gpg --encrypt -r 对方指纹 file.txt      # 加密给对方（生成 file.txt.gpg）
gpg --decrypt file.txt.gpg > out.txt   # 解密
gpg --dearmor a.asc > a.gpg            # Armor ↔ 二进制互转
gpg --export-secret-keys --armor 邮箱  # 导出私钥（备份，注意保管！）
```

## 权威文档

- GnuPG 官方文档与手册：<https://gnupg.org/documentation/>
- `man gpg`（各发行版随 gnupg 安装；Debian 在线版：<https://manpages.debian.org/gnupg/gpg.1.en.html>）
- RFC 4880 / RFC 9580（OpenPGP 报文与 Armor 的正式定义；本项目 Armor 输出遵循 RFC 4880）
- GNU Privacy Guard 指南（Gentoo Wiki 等社区文档对日常操作覆盖较全）

## 安全提示（与本项目相关的红线）

- 私钥永远不离开你的机器；本工具只接触公钥。
- 备份私钥用 `--export-secret-keys` 后离线保存；泄露的私钥 = 靓号资产即刻失守。
- 拿到别人的公钥先核指纹再加密（防中间人替换公钥）。
