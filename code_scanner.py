import os
import ast
import asyncio
import aiofiles
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Generator, Optional, Any
import threading
import logging
import time
from functools import partial

# 配置日志
default_logger = logging.getLogger(__name__)
default_logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
default_logger.addHandler(handler)


class AsyncCodeAnalyzer:
    """异步代码分析器（结合线程池与协程）"""
    def __init__(self, max_workers=10):
        self.executor = ThreadPoolExecutor(max_workers)
        self.ignore_dirs = {'__pycache__', '.git', 'venv'}
        self.semaphore = asyncio.Semaphore(50)  # 并发控制[7](@ref)
        self.logger = logging.getLogger(__name__).getChild('AsyncCodeAnalyzer')

    async def _parse_python_file(self, file_path: Path) -> List[Dict]:
        """异步解析Python文件结构（含异常处理）"""
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                content = await f.read()
            
            tree = ast.parse(content)
            classes = [
                {
                    'name': node.name,
                    'type': 'class',
                    'methods': [
                        {
                            'name': m.name,
                            'doc': ast.get_docstring(m) or '',
                            'lineno': m.lineno
                        } for m in node.body if isinstance(m, ast.FunctionDef)
                    ],
                    'doc': ast.get_docstring(node) or ''
                } for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
            ]
            self.logger.info(f"成功解析文件: {file_path}，找到{len(classes)}个类")
            return classes
        except (SyntaxError, UnicodeDecodeError) as e:
            self.logger.error(f"解析失败：{file_path} - {str(e)}")
            return []

    async def _scan_directory(self, directory: Path) -> Generator[Dict, None, None]:
        """增强型目录扫描（支持进度反馈）"""
        try:
            entries = await asyncio.to_thread(os.listdir, directory)
            for entry in sorted(entries, key=lambda x: x.lower()):
                path = directory / entry
                
                # 只扫描当前目录下的子目录和文件
                if path.is_dir() and entry not in self.ignore_dirs:
                    children = [child async for child in self._scan_directory(path)]
                    yield {
                        'name': entry,
                        'type': 'directory',
                        'path': str(path),
                        'children': children
                    }
                elif path.is_file():
                    node = {
                        'name': entry,
                        'type': 'file',
                        'path': str(path),
                        'language': 'python' if path.suffix == '.py' else 'other'
                    }
                    if node['language'] == 'python':
                        node['classes'] = await self._parse_python_file(path)
                    yield node
        except PermissionError:
            self.logger.warning(f"权限不足，无法访问目录: {directory}")
        except Exception as e:
            self.logger.error(f"扫描目录失败 {directory}: {str(e)}", exc_info=True)


class TreeViewApp(tk.Tk):
    """现代化GUI界面（集成异步任务管理）"""
    def __init__(self):
        super().__init__()
        self.title("智能代码分析器")
        self.geometry("1200x800")
        self.logger = logging.getLogger(__name__).getChild('TreeViewApp')
        self.analyzer = AsyncCodeAnalyzer()
        self._history = []
        self._create_ui_components()
        self._setup_async_loop()
        self.current_task = None  # 当前任务
        self.scan_start_time = 0  # 扫描开始时间

    def _create_ui_components(self):
        """创建带输入输出组件的界面"""
        # 配置样式
        style = ttk.Style()
        style.configure('Header.TLabel', font=('微软雅黑', 10, 'bold'))
        
        # 输入控制面板
        input_frame = ttk.Frame(self, padding=10)
        input_frame.pack(fill=tk.X)
        
        # 搜索框和历史记录
        self.path_entry = ttk.Combobox(
            input_frame, 
            width=60, 
            font=('微软雅黑', 10),
            values=self._history,
            postcommand=self._update_history  # 历史记录更新回调
        )
        self.path_entry.pack(side=tk.LEFT, padx=5)
        
        # 工具提示
        self.path_tooltip = tk.Label(
            input_frame, 
            text="输入或选择要扫描的目录路径",
            font=('微软雅黑', 8),
            fg='gray'
        )
        self.path_tooltip.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(input_frame, text="浏览", command=self._browse_dir).pack(side=tk.LEFT)
        ttk.Button(input_frame, text="开始扫描", command=self._start_async_scan).pack(side=tk.LEFT, padx=10)
        ttk.Button(input_frame, text="停止", command=self._stop_current_scan).pack(side=tk.LEFT, padx=5)
        
        # 进度显示条
        self.progress = ttk.Progressbar(self, mode='determinate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)
        
        # 树形视图容器
        tree_container = ttk.Frame(self)
        tree_container.pack(fill=tk.BOTH, expand=True, padx=10)
        
        # 树形视图
        self.tree = ttk.Treeview(
            tree_container, 
            columns=('type', 'path', 'size'), 
            selectmode='browse'
        )
        self.tree.heading('#0', text='名称')
        self.tree.heading('type', text='类型')
        self.tree.heading('path', text='路径')
        self.tree.heading('size', text='大小')
        
        # 添加滚动条
        yscrollbar = ttk.Scrollbar(tree_container, orient='vertical', command=self.tree.yview)
        xscrollbar = ttk.Scrollbar(self, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscrollbar.set, xscrollcommand=xscrollbar.set)
        
        self.tree.pack(side='left', fill=tk.BOTH, expand=True)
        yscrollbar.pack(side='right', fill='y')
        xscrollbar.pack(side='bottom', fill='x')
        
        # 详情面板
        self.detail_text = tk.Text(self, height=15, wrap=tk.WORD)
        self.detail_text.pack(fill=tk.BOTH, padx=10, pady=5)
        
        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(self, textvariable=self.status_var)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=2)
        
        # 右键菜单
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="导出JSON", command=self.export_json)
        self.menu.add_command(label="保存结构树", command=self.save_structure_tree)
        self.menu.add_command(label="保存结构文本", command=self.save_structure_text)
        self.menu.add_command(label="保存目录结构", command=self.save_directory_structure)
        self.menu.add_separator()
        self.menu.add_command(label="导出为Markdown", command=self.save_as_markdown)
        self.menu.add_command(label="导出为HTML", command=self.save_as_html)
        self.menu.add_command(label="保存精简结构", command=self.save_simplified_structure)  # 确保新增的精简结构菜单项正确显示
        self.menu.add_separator()
        self.menu.add_command(label="复制路径", command=self.copy_path)
        self.menu.add_command(label="打开文件", command=self.open_selected_item)
        self.menu.add_separator()
        self.menu.add_command(label="刷新", command=self._refresh_current_dir)
        self.menu.add_command(label="取消", command=self._stop_current_scan)
        self.tree.bind("<Button-3>", self._show_context_menu)
        self.tree.bind('<Double-1>', self._on_double_click)

    def export_json(self):
        """导出JSON结构"""
        try:
            self.logger.info("开始导出JSON")
            item = self.tree.focus()
            if not item:
                messagebox.showerror("错误", "请选择要导出的节点")
                return
                
            path = self.tree.item(item, 'values')[1]
            
            def build_dict(parent):
                return {
                    'name': self.tree.item(parent, 'text'),
                    'type': self.tree.item(parent, 'values')[0],
                    'path': self.tree.item(parent, 'values')[1],
                    'doc': self.tree.item(parent, 'values')[2],  # 类/方法的注释
                    'children': [build_dict(child) for child in self.tree.get_children(parent)]
                }
            
            data = build_dict(item)
            save_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON文件", "*.json")],
                initialfile=f"{Path(path).name}_structure.json"
            )
            
            if save_path:
                with open(save_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("导出成功", f"已保存为{save_path}")
                self.logger.info(f"JSON导出成功: {save_path}")
                
        except Exception as e:
            self.logger.error(f"导出JSON失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"导出JSON时发生错误: {str(e)}")

    def save_structure_tree(self):
        """保存整个结构树到文件，包含类方法及其注释信息"""
        try:
            self.logger.info("开始保存结构树")
            # 确保根节点存在
            if not self.tree.get_children():
                messagebox.showerror("错误", "没有可保存的结构树")
                return
            
            # 获取根节点
            root_item = self.tree.get_children()[0]
            
            # 构建结构树数据
            data = self._build_json_structure(root_item)
            
            # 选择保存路径
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("结构树文件", "*.json"), ("所有文件", "*.*")],
                title="保存结构树"
            )
            
            if not file_path:
                return
            
            # 保存结构树
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            messagebox.showinfo("成功", f"结构树已保存至: {file_path}")
            self.logger.info(f"结构树保存成功: {file_path}")
            
        except Exception as e:
            self.logger.error(f"保存结构树失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"保存结构树时发生错误: {str(e)}")

    def _build_json_structure(self, item):
        """递归构建包含注释的JSON结构"""
        if not item:
            return None
            
        name = self.tree.item(item, 'text')
        item_type, path, doc = self.tree.item(item, 'values')

        children = [self._build_json_structure(child) for child in self.tree.get_children(item)]
        
        return {
            "name": name,
            "type": item_type,
            "path": path,
            "doc": doc,
            "children": children
        }

    def _setup_async_loop(self):
        """初始化异步事件循环线程"""
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_async_loop, daemon=True)
        self.thread.start()
        # 设置日志记录
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename='code_analyzer.log',
            filemode='w',
            encoding='utf-8'
        )

    def _run_async_loop(self):
        """运行异步事件循环"""
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def _browse_dir(self):
        """目录选择对话框"""
        try:
            self.logger.info("正在打开目录选择对话框")
            initial_dir = self.path_entry.get() or os.path.expanduser("~")
            if path := filedialog.askdirectory(
                initialdir=initial_dir,
                title="选择代码目录"
            ):
                self.path_entry.set(path)
                if path not in self._history:
                    self._history.insert(0, path)
                    self.path_entry.configure(values=self._history[:10])
                self.logger.debug(f"用户选择目录: {path}")
        except Exception as e:
            self.logger.error(f"浏览目录失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"浏览目录时发生错误: {str(e)}")

    def _start_async_scan(self):
        """启动异步扫描任务"""
        try:
            self.logger.info("开始新扫描任务")
            path = self.path_entry.get().strip()
            if not path or not Path(path).exists():
                messagebox.showerror("错误", "请输入有效目录路径")
                return
                
            # 清空之前的扫描结果
            self.tree.delete(*self.tree.get_children())
            
            # 记录开始时间
            self.scan_start_time = time.time()
            
            # 获取总文件数用于进度条
            total_files = sum(1 for _ in Path(path).glob('**/*') if _.is_file())
            if total_files == 0:
                messagebox.showinfo("提示", "目标目录为空")
                return
                
            self.progress['maximum'] = total_files
            self.status_var.set(f"扫描中... (0/{total_files})")
            
            # 创建扫描任务
            self.current_task = asyncio.run_coroutine_threadsafe(
                self._perform_scan(Path(path)), 
                self.loop
            )
            self.current_task.add_done_callback(partial(self._scan_complete_callback, path=path))
            
        except Exception as e:
            self.logger.error(f"启动扫描任务失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"启动扫描任务时发生错误: {str(e)}")

    async def _perform_scan(self, path: Path):
        """执行扫描任务并更新进度"""
        try:
            self.logger.debug(f"开始扫描目录: {path}")
            root_node = self.tree.insert('', 'end', text=path.name, values=('directory', str(path), ''))
            scanned_files = 0
            
            async for node in self.analyzer._scan_directory(path):
                # 如果任务被取消，立即退出
                if asyncio.current_task().cancelled():
                    return
                
                # 插入节点
                await self.loop.run_in_executor(
                    None, 
                    lambda: self.after(0, self._insert_tree_node, root_node, node)
                )
                
                # 更新文件计数
                if node['type'] == 'file':
                    scanned_files += 1
                    # 每处理10个文件更新一次UI
                    if scanned_files % 10 == 0:
                        self.progress.step(10)
                        self.status_var.set(f"扫描中... ({scanned_files}/{self.progress['maximum']})")
            
            return scanned_files
            
        except Exception as e:
            self.logger.error(f"扫描任务执行失败: {str(e)}", exc_info=True)
            raise

    def _stop_current_scan(self):
        """停止当前扫描任务"""
        try:
            self.logger.info("停止当前扫描任务")
            if self.current_task and not self.current_task.done():
                self.current_task.cancel()
                self.current_task = None
                self.status_var.set("扫描已取消")
                self.progress.stop()
                
            # 清除输入框提示
            self.path_tooltip.config(text="输入或选择要扫描的目录路径")
            
        except Exception as e:
            self.logger.error(f"停止扫描任务失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"停止扫描任务时发生错误: {str(e)}")

    def _refresh_current_dir(self):
        """刷新当前目录"""
        try:
            self.logger.info("刷新当前目录")
            item = self.tree.focus()
            if item:
                path = self.tree.item(item, 'values')[1]
                if os.path.isdir(path):
                    self.path_entry.set(path)
                    self._start_async_scan()
            
        except Exception as e:
            self.logger.error(f"刷新目录失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"刷新目录时发生错误: {str(e)}")

    def _update_history(self):
        """更新历史记录下拉框"""
        try:
            self.logger.debug("更新历史记录")
            self.path_entry.configure(values=self._history[:10])
            
        except Exception as e:
            self.logger.error(f"更新历史记录失败: {str(e)}", exc_info=True)

    def _insert_tree_node(self, parent, node):
        """线程安全插入树节点[1](@ref)"""
        try:
            self.logger.debug(f"插入节点: {node['name']} ({node['type']})")
            
            # 获取文件大小
            size = ""
            if node['type'] == 'file' and os.path.isfile(node['path']):
                size = os.path.getsize(node['path'])
                size = f"{size/1024:.1f} KB" if size < 1024*1024 else f"{size/(1024*1024):.1f} MB"
            
            # 插入节点
            item = self.tree.insert(parent, 'end', text=node['name'],
                                  values=(node['type'], node['path'], size))
            
            if node['type'] == 'directory':
                # 对目录添加图标和子节点数量统计
                self.tree.item(item, open=False)
                child_count = sum(1 for _ in node.get('children', []))
                self.tree.item(item, text=f"{node['name']} ({child_count})")
                
                for child in node.get('children', []):
                    self.after(0, self._insert_tree_node, item, child)
            elif node.get('classes'):
                # 对Python文件添加类统计
                class_count = len(node['classes'])
                self.tree.item(item, text=f"{node['name']} ({class_count} classes)")
                
                for cls in node['classes']:
                    class_node = self.tree.insert(item, 'end', text=cls['name'],
                             values=('class', '', cls['doc']))  # 存储类的注释
                    # 添加方法计数
                    method_count = len(cls['methods'])
                    self.tree.item(class_node, text=f"{cls['name']} ({method_count} methods)")
                    
                    for method in cls['methods']:
                        # 添加方法节点及其注释
                        self.tree.insert(class_node, 'end', text=method['name'],
                                       values=('method', f"Line: {method['lineno']}", method['doc']))  # 存储方法的注释
            
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.error(f"插入节点失败 {node['name']}: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"插入节点时发生错误: {str(e)}")

    def _scan_complete_callback(self, future, path):
        """扫描完成回调"""
        try:
            scanned_files = future.result()
            elapsed_time = time.time() - self.scan_start_time
            self.logger.info(f"完成目录扫描: {path}，共找到{scanned_files}个文件，耗时{elapsed_time:.2f}秒")
            self.status_var.set(f"扫描完成：{path}（{scanned_files}个文件，{elapsed_time:.2f}秒）")
            self.progress.stop()
            self.path_tooltip.config(text="输入或选择要扫描的目录路径")
            
        except asyncio.CancelledError:
            self.logger.info(f"扫描已取消: {path}")
            self.status_var.set("扫描已取消")
            self.tree.delete(*self.tree.get_children())
            self.progress.stop()
            self.path_tooltip.config(text="输入或选择要扫描的目录路径")
        except Exception as e:
            self.logger.error(f"扫描完成回调处理失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"处理扫描结果时发生错误: {str(e)}")

    def _show_context_menu(self, event):
        """显示右键菜单"""
        try:
            item = self.tree.identify('item', event.x, event.y)
            if item:
                self.logger.debug(f"显示右键菜单于节点: {self.tree.item(item, 'text')}")
                self.menu.tk_popup(event.x_root, event.y_root)
                
        except Exception as e:
            self.logger.error(f"显示右键菜单失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"显示右键菜单时发生错误: {str(e)}")
        finally:
            self.menu.unbind("<FocusOut>")
            self.menu.bind("<FocusOut>", lambda e: self.menu.unpost())

    def _on_double_click(self, event):
        """双击打开文件或目录"""
        try:
            item = self.tree.focus()
            values = self.tree.item(item, 'values')
            if len(values) > 1:
                path = values[1]
                if os.path.isfile(path):
                    self.logger.info(f"正在打开文件: {path}")
                    os.startfile(path)
                elif os.path.isdir(path):
                    self.logger.info(f"正在打开目录: {path}")
                    os.startfile(path)
            
        except Exception as e:
            self.logger.error(f"打开文件失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"打开文件时发生错误: {str(e)}")

    def copy_path(self):
        """复制路径到剪贴板"""
        try:
            self.logger.info("复制路径到剪贴板")
            item = self.tree.focus()
            if not item:
                return
                
            path = self.tree.item(item, 'values')[1]
            self.clipboard_clear()
            self.clipboard_append(path)
            self.status_var.set("路径已复制到剪贴板")
            self.logger.debug(f"复制路径: {path}")
            
        except Exception as e:
            self.logger.error(f"复制路径失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"复制路径时发生错误: {str(e)}")

    def open_selected_item(self):
        """打开选中的文件或目录"""
        try:
            item = self.tree.focus()
            if not item:
                return
                
            path = self.tree.item(item, 'values')[1]
            if os.path.exists(path):
                self.logger.info(f"打开选中项目: {path}")
                os.startfile(path)
            else:
                messagebox.showerror("错误", "路径不存在")
                
        except Exception as e:
            self.logger.error(f"打开选中项目失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"打开项目时发生错误: {str(e)}")

    def save_structure_text(self):
        """保存整个结构树为文本格式文件"""
        try:
            self.logger.info("开始保存结构文本")
            if not self.tree.get_children():
                messagebox.showerror("错误", "没有可保存的结构树")
                return
            
            # 获取根节点
            root_item = self.tree.get_children()[0]
            
            # 构建结构文本
            structure_text = self._build_tree_text(root_item)
            
            # 选择保存路径
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
                title="保存结构文本"
            )
            
            if not file_path:
                return
            
            # 保存文本文件
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(structure_text)
            
            messagebox.showinfo("成功", f"结构文本已保存至: {file_path}")
            self.logger.info(f"结构文本保存成功: {file_path}")
            
        except Exception as e:
            self.logger.error(f"保存结构文本失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"保存结构文本时发生错误: {str(e)}")

    def _build_tree_text(self, item, level=0, is_last=True, prefix=""):
        """递归构建树状文本结构"""
        # 根节点特殊处理
        if level == 0:
            result = f"{self.tree.item(item, 'text')}/\n"
            new_prefix = ""
        else:
            result = ""
            new_prefix = prefix[:-4] if level > 1 else ""
            
        children = self.tree.get_children(item)
        for i, child in enumerate(children):
            is_last_child = (i == len(children) - 1)
            
            # 构建当前层级前缀
            current_prefix = ""
            if level > 0:
                current_prefix = prefix + ("    " if is_last else "│   ")
            
            # 获取节点信息
            text = self.tree.item(child, 'text')
            values = self.tree.item(child, 'values')
            node_type, path, doc = values
            
            # 添加当前节点
            line_prefix = ("└── " if is_last_child else "├── ")
            result += f"{current_prefix}{line_prefix}{text}"
            
            # 添加注释（如果是类或方法）
            if node_type in ['class', 'method']:
                if doc:
                    # 处理多行注释，自动换行并缩进
                    lines = doc.split('\n')
                    first_line = lines[0].strip()
                    result += f"  # {first_line}\n"
                    
                    if len(lines) > 1:
                        for line in lines[1:]:
                            result += f"{current_prefix}    {line.strip()}\n"
                    continue
                
            result += "\n"
            
            # 递归处理子节点
            new_line_prefix = ("    " if is_last_child else "│   ")
            result += self._build_tree_text(child, level + 1, is_last_child, current_prefix)
            
        return result

    def save_directory_structure(self):
        """保存仅包含文件夹和文件的结构树文本文件"""
        try:
            self.logger.info("开始保存目录结构")
            if not self.tree.get_children():
                messagebox.showerror("错误", "没有可保存的结构树")
                return
            
            # 获取根节点
            root_item = self.tree.get_children()[0]
            
            # 构建目录结构文本
            structure_text = self._build_directory_tree_text(root_item)
            
            # 选择保存路径
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
                title="保存目录结构"
            )
            
            if not file_path:
                return
            
            # 保存文本文件
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(structure_text)
            
            messagebox.showinfo("成功", f"目录结构已保存至: {file_path}")
            self.logger.info(f"目录结构保存成功: {file_path}")
            
        except Exception as e:
            self.logger.error(f"保存目录结构失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"保存目录结构时发生错误: {str(e)}")

    def _build_directory_tree_text(self, item, level=0, is_last=True, prefix=""):
        """递归构建仅包含文件夹和文件的树状文本结构"""
        # 根节点特殊处理
        if level == 0:
            result = f"{self.tree.item(item, 'text')}/\n"
            new_prefix = ""
        else:
            result = ""
            new_prefix = prefix[:-4] if level > 1 else ""
            
        children = self.tree.get_children(item)
        for i, child in enumerate(children):
            is_last_child = (i == len(children) - 1)
            
            # 获取节点信息
            text = self.tree.item(child, 'text')
            values = self.tree.item(child, 'values')
            node_type, path, doc = values
            
            # 只处理目录和文件节点
            if node_type in ['directory', 'file']:
                # 构建当前层级前缀
                current_prefix = ""
                if level > 0:
                    current_prefix = prefix + ("    " if is_last else "│   ")
                
                # 添加当前节点
                line_prefix = ("└── " if is_last_child else "├── ")
                result += f"{current_prefix}{line_prefix}{text}"
                
                # 如果是Python文件显示大小（可选）
                if node_type == 'file' and text.endswith('.py'):
                    size = os.path.getsize(path)
                    result += f" ({size//1024} KB)" if size < 1024*1024 else f" ({size//(1024*1024)} MB)"
                result += "\n"
                
                # 递归处理子节点（如果是目录）
                if node_type == 'directory':
                    result += self._build_directory_tree_text(child, level + 1, is_last_child, current_prefix)
            
        return result

    def save_as_markdown(self):
        """保存结构树为Markdown格式文件"""
        try:
            self.logger.info("开始保存Markdown格式")
            if not self.tree.get_children():
                messagebox.showerror("错误", "没有可保存的结构树")
                return
            
            # 获取根节点
            root_item = self.tree.get_children()[0]
            
            # 构建Markdown内容
            content = "# 项目结构树\n\n"
            content += "``tree\n"
            content += self._build_tree_text(root_item)
            content += "```\n\n"
            content += "## 结构说明\n\n" + self._build_structure_description(root_item)
            
            # 选择保存路径
            file_path = filedialog.asksaveasfilename(
                defaultextension=".md",
                filetypes=[("Markdown文件", "*.md"), ("所有文件", "*.*")],
                title="保存Markdown文件"
            )
            
            if not file_path:
                return
            
            # 保存Markdown文件
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            messagebox.showinfo("成功", f"Markdown文件已保存至: {file_path}")
            self.logger.info(f"Markdown文件保存成功: {file_path}")
            
        except Exception as e:
            self.logger.error(f"保存Markdown文件失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"保存Markdown文件时发生错误: {str(e)}")

    def save_as_html(self):
        """保存结构树为HTML格式文件"""
        try:
            self.logger.info("开始保存HTML格式")
            if not self.tree.get_children():
                messagebox.showerror("错误", "没有可保存的结构树")
                return
            
            # 获取根节点
            root_item = self.tree.get_children()[0]
            
            # 构建HTML内容
            content = "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n    <meta charset=\"UTF-8\">\n    <title>项目结构树</title>\n    <style>\n        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 2em; }\n        h1, h2 { color: #2c3e50; }\n        pre { background-color: #f4f4f4; padding: 1em; overflow-x: auto; }\n        .structure { margin-left: 2em; }\n        .node-type { color: #7f8c8d; }\n        .docstring { color: #27ae60; font-style: italic; }\n    </style>\n</head>\n<body>\n    <h1>项目结构树</h1>\n\n    <h2>目录结构</h2>\n    <pre><code>" + self._build_tree_text(root_item).replace('<', '&lt;').replace('>', '&gt;') + "</code></pre>\n\n    <h2>详细说明</h2>\n    <div class=\"structure\">" + self._build_structure_description_html(root_item) + "</div>\n\n</body>\n</html>"
            
            # 选择保存路径
            file_path = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML文件", "*.html"), ("所有文件", "*.*")],
                title="保存HTML文件"
            )
            
            if not file_path:
                return
            
            # 保存HTML文件
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            messagebox.showinfo("成功", f"HTML文件已保存至: {file_path}")
            self.logger.info(f"HTML文件保存成功: {file_path}")
            
        except Exception as e:
            self.logger.error(f"保存HTML文件失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"保存HTML文件时发生错误: {str(e)}")

    def save_simplified_structure(self):
        """保存仅包含文件夹、文件和类方法的结构树"""
        try:
            self.logger.info("开始保存精简结构")
            if not self.tree.get_children():
                messagebox.showerror("错误", "没有可保存的结构树")
                return
            
            # 获取根节点
            root_item = self.tree.get_children()[0]
            
            # 构建选择对话框
            file_types = [
                ("JSON 文件", "*.json"),
                ("文本文件", "*.txt"),
                ("所有文件", "*.*")
            ]
            
            # 选择保存路径
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=file_types,
                title="保存精简结构"
            )
            
            if not file_path:
                return
            
            # 根据扩展名选择保存格式
            file_ext = Path(file_path).suffix.lower()
            
            if file_ext == '.json':
                # 构建JSON结构
                data = self._build_simplified_json_structure(root_item)
                
                # 保存JSON文件
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
            elif file_ext == '.txt':
                # 构建文本结构
                structure_text = self._build_simplified_tree_text(root_item)
                
                # 保存文本文件
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(structure_text)
                
            else:
                # 默认使用JSON格式
                data = self._build_simplified_json_structure(root_item)
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            
            messagebox.showinfo("成功", f"精简结构已保存至: {file_path}")
            self.logger.info(f"精简结构保存成功: {file_path}")
            
        except Exception as e:
            self.logger.error(f"保存精简结构失败: {str(e)}", exc_info=True)
            messagebox.showerror("错误", f"保存精简结构时发生错误: {str(e)}")

    def _build_simplified_json_structure(self, item):
        """构建仅包含文件夹、文件和类方法的JSON结构"""
        result = {
            "name": self.tree.item(item, 'text'),
            "type": self.tree.item(item, 'values')[0],
        }
        
        children = []
        # 收集并处理子节点
        child_nodes = []
        for child in self.tree.get_children(item):
            values = self.tree.item(child, 'values')
            node_type, path, doc = values
            
            # 只包含目录、文件和类方法节点
            if node_type in ['directory', 'file', 'class', 'method']:
                child_nodes.append((child, node_type, path, doc))
        
        # 先处理非类节点的子节点
        for child, node_type, path, doc in child_nodes:
            if node_type != 'class':
                child_data = self._build_simplified_json_structure(child)
                
                # 添加注释信息（如果是类或方法）
                if node_type in ['class', 'method'] and doc:
                    child_data["doc"] = doc
                
                children.append(child_data)
            
        # 最后处理类节点，确保包含所有方法
        for child, node_type, path, doc in child_nodes:
            if node_type == 'class':
                # 处理类节点本身
                child_data = self._build_simplified_json_structure(child)
                if doc:
                    child_data["doc"] = doc
                
                children.append(child_data)
                
                # 收集所有方法子节点
                method_children = []
                for grandchild in self.tree.get_children(child):
                    grandchild_values = self.tree.item(grandchild, 'values')
                    grandchild_type = grandchild_values[0]
                    if grandchild_type == 'method':
                        method_children.append(self._build_simplified_json_structure(grandchild))
                
                if method_children:
                    children.extend(method_children)
        
        if children:
            result["children"] = children
            
        return result

    def _build_simplified_tree_text(self, item, level=0, is_last=True, prefix=""):
        """构建仅包含文件夹、文件和类方法的树状文本结构"""
        # 根节点特殊处理
        if level == 0:
            result = f"{self.tree.item(item, 'text')}/\n"
            new_prefix = ""
        else:
            result = ""
            new_prefix = prefix[:-4] if level > 1 else ""
            
        children = self.tree.get_children(item)
        for i, child in enumerate(children):
            is_last_child = (i == len(children) - 1)
            
            # 构建当前层级前缀
            current_prefix = ""
            if level > 0:
                current_prefix = prefix + ("    " if is_last else "│   ")
            
            # 获取节点信息
            text = self.tree.item(child, 'text')
            values = self.tree.item(child, 'values')
            node_type, path, doc = values
            
            # 只处理目录、文件、类和方法节点
            if node_type in ['directory', 'file', 'class', 'method']:
                # 添加当前节点
                line_prefix = ("└── " if is_last_child else "├── ")
                result += f"{current_prefix}{line_prefix}{text}"
                
                # 如果是Python文件显示大小（可选）
                if node_type == 'file' and text.endswith('.py'):
                    try:
                        size = os.path.getsize(path)
                        result += f" ({size//1024} KB)" if size < 1024*1024 else f" ({size//(1024*1024)} MB)"
                    except:
                        pass
                
                # 添加注释（如果是类或方法）
                if node_type in ['class', 'method']:
                    if doc:
                        # 处理多行注释，自动换行并缩进
                        lines = doc.split('\n')
                        first_line = lines[0].strip()
                        result += f"  # {first_line}\n"
                        
                        if len(lines) > 1:
                            for line in lines[1:]:
                                result += f"{current_prefix}    {line.strip()}\n"
                        
                # 对于类节点，确保显示所有方法
                if node_type == 'class':
                    # 强制展开类的方法列表
                    method_children = []
                    for grandchild in self.tree.get_children(child):
                        if self.tree.item(grandchild, 'values')[0] == 'method':
                            method_children.append(grandchild)
                    
                    # 显示方法数量
                    if method_children:
                        result += f" ({len(method_children)} methods)\n"
                        # 递归显示所有方法
                        for grandchild in method_children:
                            result += self._build_simplified_tree_text(grandchild, level + 1, is_last_child, current_prefix)
                    else:
                        result += "\n"
                else:
                    result += "\n"
                
                # 递归处理子节点
                new_line_prefix = ("    " if is_last_child else "│   ")
                result += self._build_simplified_tree_text(child, level + 1, is_last_child, current_prefix)
            
        return result

    def _build_structure_description(self, item):
        """构建文本结构说明"""
        result = ""
        children = self.tree.get_children(item)
        for child in children:
            text = self.tree.item(child, 'text')
            values = self.tree.item(child, 'values')
            node_type, path, doc = values
            
            if node_type == 'directory':
                result += f"### {text}/\n\n"
                # 处理多行描述
                if doc:
                    lines = doc.split('\n')
                    result += f"{lines[0].strip()}\n\n"
                    if len(lines) > 1:
                        for line in lines[1:]:
                            result += f"{line.strip()}\n\n"
                else:
                    result += "无描述\n\n"
                result += self._build_structure_description(child)
            elif node_type == 'file':
                result += f"#### {text}  \n\n"
                # 处理多行描述
                if doc:
                    lines = doc.split('\n')
                    result += f"{lines[0].strip()}\n\n"
                    if len(lines) > 1:
                        for line in lines[1:]:
                            result += f"{line.strip()}\n\n"
                else:
                    result += "无描述\n\n"
            
        return result

    def _build_structure_description_html(self, item):
        """构建HTML结构说明"""
        result = ""
        children = self.tree.get_children(item)
        for child in children:
            text = self.tree.item(child, 'text')
            values = self.tree.item(child, 'values')
            node_type, path, doc = values
            
            if node_type == 'directory':
                result += f"<h3>{text}/</h3>\n"
                # 处理多行描述
                if doc:
                    lines = doc.split('\n')
                    result += f"<p>{lines[0].strip()}</p>\n"
                    if len(lines) > 1:
                        result += "<ul>\n"
                        for line in lines[1:]:
                            result += f"<li>{line.strip()}</li>\n"
                        result += "</ul>\n"
                else:
                    result += "<p>无描述</p>\n"
                
                result += f"<div class=\"structure\">{self._build_structure_description_html(child)}</div>\n"
            elif node_type == 'file':
                result += f"<h4>{text}</h4>\n"
                # 处理多行描述
                if doc:
                    lines = doc.split('\n')
                    result += f"<p>{lines[0].strip()}</p>\n"
                    if len(lines) > 1:
                        result += "<ul>\n"
                        for line in lines[1:]:
                            result += f"<li>{line.strip()}</li>\n"
                        result += "</ul>\n"
                else:
                    result += "<p>无描述</p>\n"
            
        return result


async def main():
    """异步主程序"""
    try:
        app = TreeViewApp()
        app.mainloop()
    except Exception as e:
        logging.getLogger(__name__).critical(f"应用程序崩溃: {str(e)}", exc_info=True)
        messagebox.showerror("致命错误", f"应用程序发生致命错误:\n{str(e)}")

if __name__ == "__main__":
    # 启动应用程序
    asyncio.run(main())
