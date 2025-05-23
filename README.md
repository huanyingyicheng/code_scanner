# 代码结构扫描器

这是一个用于分析和可视化Python项目结构的工具，能够扫描目录并显示详细的代码结构信息，包括类、方法及其注释内容。

## 功能特性

- **目录扫描**：递归扫描指定目录下的所有文件和子目录
- **Python代码分析**：解析Python文件，提取类和方法定义及注释
- **结构展示**：以树状图形式展示项目结构
- **多种导出格式**：支持导出为JSON、文本、Markdown和HTML格式
- **精简结构导出**：可选择性地导出关键结构信息，包含类和方法及其注释

## 主要功能界面

## 使用方法

1. 启动程序
2. 点击"浏览"选择要分析的目录
3. 点击"开始扫描"进行代码结构分析
4. 在树状图中查看详细的代码结构
5. 可使用右键菜单导出结构信息为不同格式

## 导出功能说明

| 格式       | 特点描述 |
|------------|----------|
| JSON       | 包含完整结构信息，适合程序解析 |
| 文本       | 简洁的树状结构显示 |
| Markdown   | 支持格式化的结构展示 |
| HTML       | 可生成带样式的网页版结构图 |
| 精简结构   | 仅包含关键结构信息，突出显示类和方法 |

## 技术实现

- 使用Python的ast模块解析代码结构
- Tkinter构建图形界面
- 支持异步扫描，提高大项目处理效率
- 多线程处理确保界面响应流畅

## 开发者信息

- 当前版本: 1.0
- 开发者: huanyingyicheng
- 开发日期: 2025年4月
- 许可协议: MIT License
