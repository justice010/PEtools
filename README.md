# PEtools - 轻量级 PE 文件解析器

![Language](https://img.shields.io/badge/Language-C%2B%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Win32-green)
![License](https://img.shields.io/badge/License-MIT-orange)

一个基于 C++17 开发的 Windows 可执行文件 (PE) 解析工具。专为逆向工程学习者设计，代码结构清晰，注释详尽。

## ✨ 主要功能

- [x] **Header 解析**：解析 DOS 头部、NT 头部（FileHeader & OptionalHeader）。
- [x] **节表遍历**：详细列出所有 Section 的名称、虚拟大小、原始数据大小及属性。
- [x] **目录预览**：支持 Data Directory 基础解析（如导入表预览）。
- [x] **地址转换**：内置 RVA (Relative Virtual Address) 与 FOA (File Offset Address) 转换逻辑。

## 🛠️ 编译与运行

- **环境**: Visual Studio 2022 (v143)
- **SDK**: Windows 10 / 11 SDK
- **注意**: **必须在顶部工具栏将构建配置切换为 x86 (Win32)**，否则由于 PE32 结构体定义差异会导致编译报错。

## 🚀 快速开始

1. 克隆项目：`git clone https://github.com/justice010/PEtools.git`
2. 使用 VS2022 打开 `PEtools.sln`。
3. 确保配置为 `Debug | x86`，按 `F5` 编译运行。

## 📸 运行预览

> ![alt text](image.png)

---

_本项目仅供技术交流与学习使用。_
