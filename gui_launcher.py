import os
import sys
import json
import subprocess
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QTreeWidget, QTreeWidgetItem, 
                             QMessageBox, QDialog, QLabel, QLineEdit, QFileDialog, 
                             QHeaderView, QTextEdit, QSplitter, QMdiArea, QMdiSubWindow,
                             QStyleFactory, QCheckBox, QComboBox, QMenu, QToolButton, QFrame)
from PyQt6.QtCore import Qt, QProcess, QByteArray, QThread, pyqtSignal, QRegularExpression, QTimer, QUrl
from PyQt6.QtGui import (QIcon, QBrush, QColor, QPalette, QSyntaxHighlighter, QTextCharFormat, 
                         QFont, QAction, QKeySequence, QDesktopServices, QTextCursor, QTextDocument)
from PyQt6.QtNetwork import QTcpServer, QTcpSocket, QHostAddress

import time
import datetime
import psutil
import threading
from collections import deque
from fastmcp import FastMCP

HIDDEN_DIR = os.path.join(os.getcwd(), '.auto-terminal')
os.makedirs(HIDDEN_DIR, exist_ok=True)

CONFIG_FILE = os.path.join(HIDDEN_DIR, 'config.json')
SNIPPETS_FILE = os.path.join(HIDDEN_DIR, 'snippets.json')

# Initialize the MCP Server (will be used if --mcp is passed)
mcp = FastMCP("Auto Terminal")

class ProcessManager:
    def __init__(self):
        self.processes = {}  # name -> { 'process': Popen, 'monitor': Thread, 'logs': deque, 'stats': dict }
        self.config = []
        self.lock = threading.Lock()
        self.load_config()

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    self.config = json.load(f)
            except:
                self.config = []
        else:
            self.config = []

    def get_config(self):
        self.load_config() # Reload to get latest
        return self.config

    def get_program_info(self, name):
        for prog in self.config:
            if prog.get('name') == name:
                return prog
        return None

    def start_process(self, name):
        prog = self.get_program_info(name)
        if not prog:
            raise ValueError(f"Program '{name}' not found in config.")

        command = prog.get('command', '')
        cwd = prog.get('cwd', os.getcwd())
        shell_path = prog.get('shell', '/bin/sh')

        return self._spawn_process(name, command, cwd, shell_path)

    def start_dynamic_process(self, command, name=None, cwd=None):
        if not name:
            name = f"cmd_{int(time.time())}"
        
        cwd = cwd or os.getcwd()
        shell_path = '/bin/zsh' # Default for dynamic commands

        return self._spawn_process(name, command, cwd, shell_path)

    def _spawn_process(self, name, command, cwd, shell_path):
        if name in self.processes and self.processes[name]['process'].poll() is None:
            raise RuntimeError(f"Process '{name}' is already running.")

        # Log file setup
        log_dir = os.path.join(HIDDEN_DIR, 'logs')
        os.makedirs(log_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(c for c in name if c.isalnum() or c in (' ', '_', '-')).strip().replace(' ', '_')
        log_file_path = os.path.join(log_dir, f"{safe_name}_{timestamp}.log")
        
        # Start Process
        try:
            # Using preexec_fn=os.setsid to allow killing the whole process group
            proc = subprocess.Popen(
                [shell_path, '-c', command],
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid 
            )
        except Exception as e:
            raise RuntimeError(f"Failed to start process: {e}")

        process_entry = {
            'process': proc,
            'logs': deque(maxlen=2000), # Keep last 2000 lines in memory
            'log_file_path': log_file_path,
            'log_file': open(log_file_path, 'a', encoding='utf-8'),
            'start_time': time.time(),
            'stats': {'cpu': 0.0, 'mem_mb': 0.0, 'status': 'Running'}
        }

        with self.lock:
            self.processes[name] = process_entry

        # Start IO Threads
        t_out = threading.Thread(target=self._read_stream, args=(name, proc.stdout, 'stdout'), daemon=True)
        t_err = threading.Thread(target=self._read_stream, args=(name, proc.stderr, 'stderr'), daemon=True)
        t_mon = threading.Thread(target=self._monitor_process, args=(name,), daemon=True)
        
        t_out.start()
        t_err.start()
        t_mon.start()

        return f"Started {name} (PID: {proc.pid})"

    def _read_stream(self, name, stream, stream_type):
        proc_entry = self.processes.get(name)
        if not proc_entry: return
        
        log_file = proc_entry['log_file']
        
        for line in iter(stream.readline, ''):
            if not line: break
            with self.lock:
                # Add timestamp
                ts = datetime.datetime.now().strftime("[%H:%M:%S] ")
                formatted_line = ts + line
                
                # Write to memory buffer
                proc_entry['logs'].append(formatted_line)
                
                # Write to file
                if log_file and not log_file.closed:
                    log_file.write(formatted_line)
                    log_file.flush()
        
        stream.close()

    def register_external_process(self, name, pid, log_path):
        with self.lock:
            self.processes[name] = {
                'type': 'external',
                'pid': pid,
                'log_file_path': log_path,
                'process': None, # No Popen object
                'logs': deque(maxlen=2000), 
                'start_time': time.time(),
                'stats': {'cpu': 0.0, 'mem_mb': 0.0, 'status': 'Running'}
            }
        
        # Start a monitor thread that works with PID
        t_mon = threading.Thread(target=self._monitor_process, args=(name,), daemon=True)
        t_mon.start()
        
        # Start a log reader thread (tail -f style for file)
        t_log = threading.Thread(target=self._tail_log_file, args=(name, log_path), daemon=True)
        t_log.start()
        
        return f"Registered external process {name} (PID: {pid})"

    def _tail_log_file(self, name, log_path):
        if not os.path.exists(log_path): return
        
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                # Go to end? or read from start? 
                # Since it's a new command, read from start.
                while True:
                    with self.lock:
                        if name not in self.processes: break
                        if self.processes[name]['stats']['status'] != 'Running': break
                    
                    line = f.readline()
                    if line:
                        with self.lock:
                            if name in self.processes:
                                self.processes[name]['logs'].append(line)
                    else:
                        time.sleep(0.1)
        except Exception:
            pass

    def _monitor_process(self, name):
        while True:
            with self.lock:
                if name not in self.processes: break
                proc_entry = self.processes[name]
                pid = proc_entry.get('pid')
                proc_obj = proc_entry.get('process')
            
            # Check if running
            is_running = False
            if proc_obj: # Local Popen
                if proc_obj.poll() is None:
                    is_running = True
            elif pid: # External PID
                if psutil.pid_exists(pid):
                     is_running = True
            
            if not is_running:
                # Process finished
                with self.lock:
                    if name in self.processes:
                        self.processes[name]['stats']['status'] = 'Stopped'
                        if 'log_file' in self.processes[name] and not self.processes[name]['log_file'].closed:
                            self.processes[name]['log_file'].close()
                break

            try:
                p = psutil.Process(pid)
                with p.oneshot():
                    cpu = p.cpu_percent()
                    mem = p.memory_info().rss / 1024 / 1024
                    
                with self.lock:
                    if name in self.processes:
                        self.processes[name]['stats']['cpu'] = cpu
                        self.processes[name]['stats']['mem_mb'] = mem
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                 # Process might have died just now
                with self.lock:
                    if name in self.processes:
                        self.processes[name]['stats']['status'] = 'Stopped'
                break
            
            time.sleep(2)

    def stop_process(self, name):
        with self.lock:
            if name not in self.processes:
                raise ValueError(f"Process {name} is not running.")
            
            proc_entry = self.processes[name]
            proc = proc_entry.get('process')
            pid = proc_entry.get('pid')
            
            if proc:
                if proc.poll() is None:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    except:
                        proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            elif pid:
                # External process kill
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass # Process might be gone
            
            # Clean up
            if 'log_file' in proc_entry and not proc_entry['log_file'].closed:
                proc_entry['log_file'].close()
            
            del self.processes[name]
            
        return f"Stopped {name}"

    def write_input(self, name, text):
        with self.lock:
            if name not in self.processes:
                raise ValueError(f"Process {name} is not running.")
            
            proc = self.processes[name].get('process')
            if proc and proc.stdin:
                try:
                    proc.stdin.write(text + "\n")
                    proc.stdin.flush()
                except Exception as e:
                    raise RuntimeError(f"Failed to write input: {e}")
            else:
                # External process input? 
                # We can't easily write to stdin of external PID unless we use IPC to GUI.
                # For now, raise error or ignore.
                raise RuntimeError("Cannot write input to external process yet.")

    def get_logs(self, name, lines=50):
        with self.lock:
            if name not in self.processes:
                return "Process not running (no active logs in memory)."
            
            all_logs = list(self.processes[name]['logs'])
            return "".join(all_logs[-lines:])

    def get_status(self, name):
        with self.lock:
            if name in self.processes:
                stats = self.processes[name]['stats']
                uptime = int(time.time() - self.processes[name]['start_time'])
                pid = self.processes[name].get('pid')
                if not pid and self.processes[name].get('process'):
                     pid = self.processes[name]['process'].pid
                     
                return {
                    "status": self.processes[name]['stats']['status'],
                    "pid": pid,
                    "cpu_percent": stats['cpu'],
                    "memory_mb": stats['mem_mb'],
                    "uptime_seconds": uptime
                }
            else:
                return {"status": "Stopped"}

    def get_all_statuses(self):
        statuses = {}
        # Load config to get all potential names
        self.load_config()
        # Add running dynamic processes too
        with self.lock:
             running_names = list(self.processes.keys())
             
        for prog in self.config:
            name = prog['name']
            statuses[name] = self.get_status(name)
            if name in running_names: running_names.remove(name)
            
        # Add dynamic ones
        for name in running_names:
            statuses[name] = self.get_status(name)
            
        return statuses

pm = ProcessManager()

def try_gui_execution(command, name, cwd):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect(('127.0.0.1', 65432))
            
            req = {
                "action": "start",
                "name": name,
                "command": command,
                "cwd": cwd
            }
            s.sendall(json.dumps(req).encode('utf-8'))
            
            data = s.recv(4096)
            resp = json.loads(data.decode('utf-8'))
            
            if resp.get('status') == 'success':
                return resp
    except Exception:
        pass
    return None

import signal

class ConsoleInput(QLineEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.history = []
        self.history_index = -1

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_C and (event.modifiers() & Qt.KeyboardModifier.ControlModifier):
            if hasattr(self.parent(), 'send_sigint'):
                self.parent().send_sigint()
        elif event.key() == Qt.Key.Key_Up:
            self.navigate_history(1)
        elif event.key() == Qt.Key.Key_Down:
            self.navigate_history(-1)
        else:
            super().keyPressEvent(event)

    def add_to_history(self, cmd):
        if cmd and (not self.history or self.history[-1] != cmd):
            self.history.append(cmd)
        self.history_index = len(self.history)

    def navigate_history(self, direction):
        if not self.history:
            return
            
        # direction: 1 for Up (older), -1 for Down (newer)
        # But usually Up means "previous" (index - 1)
        
        if direction == 1: # Up Arrow
            if self.history_index > 0:
                self.history_index -= 1
                self.setText(self.history[self.history_index])
        elif direction == -1: # Down Arrow
            if self.history_index < len(self.history) - 1:
                self.history_index += 1
                self.setText(self.history[self.history_index])
            else:
                self.history_index = len(self.history)
                self.clear()

class MonitorThread(QThread):
    stats_signal = pyqtSignal(str)

    def __init__(self, pid):
        super().__init__()
        self.pid = pid
        self.running = True

    def run(self):
        process = psutil.Process(self.pid) if self.pid else None
        start_time = time.time()
        
        while self.running and self.pid:
            try:
                if not psutil.pid_exists(self.pid):
                    break
                
                # Re-acquire process if needed, main logic
                if not process:
                    try:
                        process = psutil.Process(self.pid)
                    except:
                        break

                # Get stats
                with process.oneshot():
                    cpu_percent = process.cpu_percent()
                    mem_info = process.memory_info()
                    mem_mb = mem_info.rss / 1024 / 1024
                
                # Uptime
                uptime_sec = int(time.time() - start_time)
                uptime_str = str(datetime.timedelta(seconds=uptime_sec))

                stats_text = f"CPU: {cpu_percent:.1f}% | MEM: {mem_mb:.1f}MB | Time: {uptime_str}"
                self.stats_signal.emit(stats_text)

                self.sleep(1) # sleep 1 second
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                break

    def stop(self):
        self.running = False
        self.wait()

class LogHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules = []

        # Error - Red
        error_fmt = QTextCharFormat()
        error_fmt.setForeground(QColor("#FF5F56"))
        error_fmt.setFontWeight(QFont.Weight.Bold)
        self.rules.append((QRegularExpression("(?i)error|exception|fail|fatal"), error_fmt))

        # Warning - Yellow
        warn_fmt = QTextCharFormat()
        warn_fmt.setForeground(QColor("#FFBD2E"))
        warn_fmt.setFontWeight(QFont.Weight.Bold)
        self.rules.append((QRegularExpression("(?i)warn|warning"), warn_fmt))

        # Info - Green
        info_fmt = QTextCharFormat()
        info_fmt.setForeground(QColor("#27C93F"))
        self.rules.append((QRegularExpression("(?i)info|success|done"), info_fmt))
        
        # Timestamp - Gray
        time_fmt = QTextCharFormat()
        time_fmt.setForeground(QColor("#808080"))
        self.rules.append((QRegularExpression(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"), time_fmt))
        
        # URLs - Blue Underline (Visual only, clicking handled in mouse event)
        url_fmt = QTextCharFormat()
        url_fmt.setForeground(QColor("#4da6ff"))
        url_fmt.setFontUnderline(True)
        # Simple URL regex
        self.rules.append((QRegularExpression(r"https?://\S+"), url_fmt))

    def highlightBlock(self, text):
        for pattern, format in self.rules:
            match_iterator = pattern.globalMatch(text)
            while match_iterator.hasNext():
                match = match_iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)

class TerminalOutput(QTextEdit):
    def mouseReleaseEvent(self, event):
        # Handle Smart Links
        cursor = self.cursorForPosition(event.pos())
        cursor.select(QTextCursor.SelectionType.WordUnderCursor)
        text = cursor.selectedText()
        
        # Check if text looks like a URL (simple check)
        # Using a wider selection around cursor might be needed for long URLs...
        # A Better way: get the full block text and check what's at cursor position.
        
        block_text = cursor.block().text()
        pos_in_block = cursor.positionInBlock()
        
        # Simple regex find all URLs in block
        url_regex = QRegularExpression(r"https?://\S+")
        match_iter = url_regex.globalMatch(block_text)
        
        clicked_url = None
        while match_iter.hasNext():
            match = match_iter.next()
            start = match.capturedStart()
            end = match.capturedEnd()
            if start <= pos_in_block <= end:
                clicked_url = match.captured()
                break
        
        if clicked_url:
            QDesktopServices.openUrl(QUrl(clicked_url))
        
        super().mouseReleaseEvent(event)

class TerminalTab(QWidget):
    def __init__(self, program):
        super().__init__()
        self.program = program
        self.process = None
        self.init_ui()
        self.start_process()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Top Bar: Status + Search
        top_layout = QHBoxLayout()
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #808080; font-size: 11px;")
        top_layout.addWidget(self.status_label)
        
        top_layout.addStretch()
        
        # Search Bar (Initially Hidden)
        self.search_frame = QFrame()
        self.search_frame.setVisible(False)
        sf_layout = QHBoxLayout(self.search_frame)
        sf_layout.setContentsMargins(0, 0, 0, 0)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Find...")
        self.search_input.returnPressed.connect(self.find_next)
        self.search_input.setFixedWidth(120)
        sf_layout.addWidget(self.search_input)
        
        # Use global styles for buttons
        
        btn_next = QPushButton("↓")
        btn_next.setFixedSize(22, 22)
        btn_next.clicked.connect(self.find_next)
        sf_layout.addWidget(btn_next)
        
        btn_prev = QPushButton("↑")
        btn_prev.setFixedSize(22, 22)
        btn_prev.clicked.connect(self.find_prev)
        sf_layout.addWidget(btn_prev)
        
        btn_close_find = QPushButton("x")
        btn_close_find.setFixedSize(22, 22)
        btn_close_find.clicked.connect(lambda: self.search_frame.setVisible(False))
        sf_layout.addWidget(btn_close_find)
        
        top_layout.addWidget(self.search_frame)
        
        layout.addLayout(top_layout)

        # Use a consistent style for small utility buttons
        small_btn_style = """
            QPushButton {
                padding: 0px;
                border-radius: 4px;
                background-color: #323232;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #404040; }
            QPushButton:pressed { background-color: #222222; }
        """
        
        btn_next.setStyleSheet(small_btn_style)
        btn_prev.setStyleSheet(small_btn_style)
        btn_close_find.setStyleSheet(small_btn_style)

        # Terminal Output Area
        self.terminal_output = TerminalOutput()
        self.terminal_output.setReadOnly(True)
        # Font setup for Zoom
        font = QFont('Menlo', 12)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.terminal_output.setFont(font)
        
        # Highlighter
        self.highlighter = LogHighlighter(self.terminal_output.document())
        
        # Styles
        self.terminal_output.setStyleSheet("""
            QTextEdit { 
                background-color: #151515; 
                color: white; 
                border: none; 
            }
            QScrollBar:vertical {
                border: none;
                background: #151515;
                width: 12px;
                margin: 0px 0px 0px 0px;
            }
            QScrollBar::handle:vertical {
                background: #424242;
                min-height: 20px;
                border-radius: 6px;
                margin: 2px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
        """)
        layout.addWidget(self.terminal_output)
        
        # Input Area
        input_layout = QHBoxLayout()
        self.terminal_input = ConsoleInput(self)
        self.terminal_input.setPlaceholderText("Enter command... (Ctrl+C: Interrupt, Cmd+F: Find)")
        self.terminal_input.returnPressed.connect(self.send_input)
        input_layout.addWidget(self.terminal_input)
        
        self.btn_send = QPushButton("Send")
        self.btn_send.clicked.connect(self.send_input)
        input_layout.addWidget(self.btn_send)
        
        layout.addLayout(input_layout)
        
        # Control Buttons
        control_layout = QHBoxLayout()
        
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.clicked.connect(self.stop_process)
        control_layout.addWidget(self.btn_stop)
        
        self.btn_restart = QPushButton("Restart")
        self.btn_restart.clicked.connect(self.restart_process)
        self.btn_restart.setEnabled(False)
        control_layout.addWidget(self.btn_restart)
        
        btn_clear = QPushButton("Clear Output")
        btn_clear.clicked.connect(self.terminal_output.clear)
        control_layout.addWidget(btn_clear)

        # Snippets Menu
        self.btn_snippets = QPushButton("Snippets")
        self.snippets_menu = QMenu()
        self.btn_snippets.setMenu(self.snippets_menu)
        control_layout.addWidget(self.btn_snippets)
        self.update_snippets_menu()
        
        # Auto Scroll Toggle
        self.chk_autoscroll = QCheckBox("Auto Scroll")
        self.chk_autoscroll.setChecked(True)
        control_layout.addWidget(self.chk_autoscroll)
        
        # Zoom Buttons (Small)
        btn_zoom_out = QPushButton("-")
        btn_zoom_out.setFixedSize(22, 22)
        btn_zoom_out.setStyleSheet(small_btn_style)
        btn_zoom_out.clicked.connect(self.zoom_out)
        control_layout.addWidget(btn_zoom_out)
        
        btn_zoom_in = QPushButton("+")
        btn_zoom_in.setFixedSize(22, 22)
        btn_zoom_in.setStyleSheet(small_btn_style)
        btn_zoom_in.clicked.connect(self.zoom_in)
        control_layout.addWidget(btn_zoom_in)
        
        layout.addLayout(control_layout)
        
        # Shortcuts
        self.shortcut_zoom_in = QAction("Zoom In", self)
        self.shortcut_zoom_in.setShortcut(QKeySequence.StandardKey.ZoomIn)
        self.shortcut_zoom_in.triggered.connect(self.zoom_in)
        self.addAction(self.shortcut_zoom_in)
        
        self.shortcut_zoom_out = QAction("Zoom Out", self)
        self.shortcut_zoom_out.setShortcut(QKeySequence.StandardKey.ZoomOut)
        self.shortcut_zoom_out.triggered.connect(self.zoom_out)
        self.addAction(self.shortcut_zoom_out)
        
        self.shortcut_find = QAction("Find", self)
        self.shortcut_find.setShortcut(QKeySequence.StandardKey.Find)
        self.shortcut_find.triggered.connect(self.toggle_find)
        self.addAction(self.shortcut_find)

    def start_process(self):
        program = self.program
        name = program.get('name', 'Unknown')
        command = program.get('command', '')
        cwd = program.get('cwd', os.getcwd())
        shell = program.get('shell', '/bin/zsh')
        
        self.terminal_output.append(f"--- Launching: {name} ---")
        self.terminal_output.append(f"Command: {command}")
        self.terminal_output.append(f"CWD: {cwd}")
        self.terminal_output.append(f"Shell: {shell}\n")
        
        # Log File Setup
        log_dir = os.path.join(os.getcwd(), '.auto-terminal', 'logs')
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(c for c in name if c.isalnum() or c in (' ', '_', '-')).strip().replace(' ', '_')
        self.log_file_path = os.path.join(log_dir, f"{safe_name}_{timestamp}.log")
        self.log_file = open(self.log_file_path, 'w', encoding='utf-8')
        
        self.process = QProcess()
        self.process.setWorkingDirectory(cwd)
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.process_finished)
        
        # Reset buttons
        self.btn_stop.setEnabled(True)
        self.btn_restart.setEnabled(False)
        self.status_label.setText("Starting...")
        
        # Run via shell
        self.process.start(shell, ['-c', command])
        
        # Start Monitor Thread
        if self.process.waitForStarted(1000):
            pid = self.process.processId()
            self.monitor_thread = MonitorThread(pid)
            self.monitor_thread.stats_signal.connect(self.update_stats)
            self.monitor_thread.start()

    def update_stats(self, stats):
        self.status_label.setText(stats)

    def zoom_in(self):
        font = self.terminal_output.font()
        font.setPointSize(font.pointSize() + 1)
        self.terminal_output.setFont(font)

    def zoom_out(self):
        font = self.terminal_output.font()
        if font.pointSize() > 6:
            font.setPointSize(font.pointSize() - 1)
            self.terminal_output.setFont(font)

    def stop_process(self):
        if hasattr(self, 'monitor_thread') and self.monitor_thread:
            self.monitor_thread.stop()
        if self.process:
            self.process.terminate()

    def send_sigint(self):
        if self.process and self.process.state() == QProcess.ProcessState.Running:
            pid = self.process.processId()
            if pid:
                try:
                    os.kill(pid, signal.SIGINT)
                    self.terminal_output.append("^C")
                except ProcessLookupError:
                    pass

    def restart_process(self):
        if self.process and self.process.state() != QProcess.ProcessState.NotRunning:
            self.stop_process()
            self.process.waitForFinished(1000)
        
        self.terminal_output.append("\n--- Restarting ---")
        self.start_process()

    def process_finished(self):
        if hasattr(self, 'monitor_thread') and self.monitor_thread:
            self.monitor_thread.stop()
            
        self.terminal_output.append(f"\n--- Process Finished ---")
        self.status_label.setText("Stopped")
        self.btn_stop.setEnabled(False)
        self.btn_restart.setEnabled(True)
        
        # Notification on Exit
        self.show_notification("Process Finished", f"{self.program.get('name')} has exited.")

    def toggle_find(self):
        self.search_frame.setVisible(not self.search_frame.isVisible())
        if self.search_frame.isVisible():
            self.search_input.setFocus()
            self.search_input.selectAll()

    def find_next(self):
        text = self.search_input.text()
        if not text: return
        self.terminal_output.find(text)

    def find_prev(self):
        text = self.search_input.text()
        if not text: return
        self.terminal_output.find(text, QTextDocument.FindFlag.FindBackward)

    def update_snippets_menu(self):
        self.snippets_menu.clear()
        
        # Load snippets
        snippets = []
        if os.path.exists(SNIPPETS_FILE):
             try:
                 with open(SNIPPETS_FILE, 'r') as f:
                     snippets = json.load(f)
             except: pass
        
        # Add Actions
        for snip in snippets:
            action = QAction(snip, self)
            action.triggered.connect(lambda checked, s=snip: self.run_snippet(s))
            self.snippets_menu.addAction(action)
            
        self.snippets_menu.addSeparator()
        add_action = QAction("+ Add Last Command", self)
        add_action.triggered.connect(self.add_last_command_to_snippets)
        self.snippets_menu.addAction(add_action)

    def run_snippet(self, command):
        self.terminal_input.setText(command)
        self.terminal_input.setFocus()

    def show_snippets(self):
        self.snippets_menu.exec(self.btn_snippets.mapToGlobal(self.btn_snippets.rect().bottomLeft()))

    def add_last_command_to_snippets(self):
        if hasattr(self.terminal_input, 'history') and self.terminal_input.history:
            last_cmd = self.terminal_input.history[-1]
            try:
                snippets = []
                if os.path.exists(SNIPPETS_FILE):
                    with open(SNIPPETS_FILE, 'r') as f: snippets = json.load(f)
                if last_cmd not in snippets:
                    snippets.append(last_cmd)
                    with open(SNIPPETS_FILE, 'w') as f: json.dump(snippets, f, indent=4)
                    self.update_snippets_menu()
                    QMessageBox.information(self, "Success", "Snippet added.")
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))
        else:
             QMessageBox.warning(self, "Info", "No history to add.")

    def add_last_command_to_snippets(self):
        if hasattr(self.terminal_input, 'history') and self.terminal_input.history:
            last_cmd = self.terminal_input.history[-1]
            try:
                snippets = []
                if os.path.exists(SNIPPETS_FILE):
                    with open(SNIPPETS_FILE, 'r') as f: snippets = json.load(f)
                if last_cmd not in snippets:
                    snippets.append(last_cmd)
                    with open(SNIPPETS_FILE, 'w') as f: json.dump(snippets, f, indent=4)
                    self.update_snippets_menu()
                    QMessageBox.information(self, "Success", "Snippet added.")
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))
        else:
             QMessageBox.warning(self, "Info", "No history to add.")

    def handle_stdout(self):
        data = self.process.readAllStandardOutput()
        text = bytes(data).decode('utf-8', errors='replace')
        
        if hasattr(self, 'log_file') and self.log_file:
            self.log_file.write(text)
            self.log_file.flush()
            
        # Use detached cursor to append without moving view
        cursor = self.terminal_output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        
        if self.chk_autoscroll.isChecked():
            self.terminal_output.setTextCursor(cursor)
            self.terminal_output.ensureCursorVisible()

    def handle_stderr(self):
        data = self.process.readAllStandardError()
        text = bytes(data).decode('utf-8', errors='replace')
        
        if hasattr(self, 'log_file') and self.log_file:
            self.log_file.write(text)
            self.log_file.flush()
            
        # Use detached cursor to append without moving view
        cursor = self.terminal_output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        
        if self.chk_autoscroll.isChecked():
            self.terminal_output.setTextCursor(cursor)
            self.terminal_output.ensureCursorVisible()

    def send_input(self):
        text = self.terminal_input.text()
        self.terminal_input.add_to_history(text)
        
        if self.process and self.process.state() == QProcess.ProcessState.Running:
            input_bytes = (text + "\n").encode('utf-8')
            self.process.write(QByteArray(input_bytes))
            self.terminal_output.insertPlainText(f"{text}\n")
            self.terminal_input.clear()
            if self.chk_autoscroll.isChecked():
                self.terminal_output.ensureCursorVisible()
        else:
            self.terminal_input.clear()

    def show_notification(self, title, message):
        try:
            cmd = f'display notification "{message}" with title "{title}"'
            os.system(f"osascript -e '{cmd}'")
        except:
            pass

class CustomTitleBar(QWidget):
    def __init__(self, parent_window, title=""):
        super().__init__()
        self.parent_window = parent_window
        self.setFixedHeight(30)
        self.setStyleSheet("background-color: #1E1E1E; border-top-left-radius: 5px; border-top-right-radius: 5px;")
        
        layout = QHBoxLayout()
        layout.setContentsMargins(10, 0, 10, 0)
        layout.setSpacing(8)
        self.setLayout(layout)
        
        # Traffic Light Buttons
        self.btn_close = self._create_circle_btn("#FF5F56")
        self.btn_min = self._create_circle_btn("#FFBD2E")
        self.btn_max = self._create_circle_btn("#27C93F")
        
        # Connect signals
        self.btn_close.clicked.connect(self.close_window)
        self.btn_min.clicked.connect(self.minimize_window)
        self.btn_max.clicked.connect(self.maximize_window)

        layout.addWidget(self.btn_close)
        layout.addWidget(self.btn_min)
        layout.addWidget(self.btn_max)
        
        # Title Label
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("color: #d0d0d0; font-weight: bold; font-family: 'SF Pro Text', 'Helvetica Neue', Helvetica, Arial, sans-serif;")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addStretch()
        layout.addWidget(self.title_label)
        layout.addStretch()
        
        dummy = QWidget()
        dummy.setFixedSize(52, 12)
        layout.addWidget(dummy)

        self.start_pos = None

    def _create_circle_btn(self, color):
        btn = QPushButton()
        btn.setFixedSize(12, 12)
        btn.setStyleSheet(f"background-color: {color}; border: none; border-radius: 6px;")
        return btn

    def close_window(self):
        if self.parent_window: self.parent_window.close()

    def minimize_window(self):
        if self.parent_window: self.parent_window.showMinimized()

    def maximize_window(self):
        if self.parent_window:
            if self.parent_window.isMaximized():
                self.parent_window.showNormal()
            else:
                self.parent_window.showMaximized()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.start_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        if self.start_pos and self.parent_window:
            delta = event.globalPosition().toPoint() - self.start_pos
            new_pos = self.parent_window.pos() + delta
            self.parent_window.move(new_pos)
            self.start_pos = event.globalPosition().toPoint()

    def mouseReleaseEvent(self, event):
        self.start_pos = None


class LauncherApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Auto Terminal")
        self.setWindowIcon(QIcon('app_icon.png'))
        self.resize(1100, 700)
        
        # Start MCP Server
        self.mcp_process = None
        self.start_mcp_server()
        
        # Start IPC Server for MCP Communication
        self.setup_ipc_server()

        
        # Apply Global Dark Theme Style
        self.setStyleSheet("""
            QMainWindow, QWidget#left_panel, QWidget#right_panel {
                background-color: #1E1E1E;
            }
            QPushButton {
                background-color: #323232;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 6px 16px;
                font-weight: 500;
                font-size: 13px;
                font-family: -apple-system, 'SF Pro Text', 'Helvetica Neue', Helvetica, Arial, sans-serif;
            }
            QPushButton:hover {
                background-color: #404040;
                color: white;
            }
            QPushButton:pressed {
                background-color: #222222;
            }
            QPushButton:disabled {
                background-color: #252525;
                color: #555555;
            }
            QLineEdit {
                background-color: #252525;
                color: white;
                border: 1px solid #333333;
                border-radius: 4px;
                padding: 4px;
            }
            QTreeWidget {
                background-color: #252525;
                color: #d0d0d0;
                border: 1px solid #333333;
                border-radius: 4px;
            }
            QHeaderView::section {
                background-color: #333333;
                color: white;
                border: none;
                padding: 4px;
            }
            QScrollBar:vertical {
                border: none;
                background: #1e1e1e;
                width: 10px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: #424242;
                min-height: 20px;
                border-radius: 4px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
            QComboBox {
                background-color: #323232;
                color: white;
                border: 1px solid #444444;
                border-radius: 6px;
                padding: 4px 8px;
            }
            QComboBox::drop-down { border: none; }
            QMenu {
                background-color: #2D2D2D;
                color: white;
                border: 1px solid #444444;
                border-radius: 4px;
            }
            QMenu::item { padding: 4px 20px; }
            QMenu::item:selected { background-color: #404040; }
            QCheckBox { color: #d0d0d0; margin-left: 10px; }
            QCheckBox::indicator {
                width: 16px; height: 16px;
                background-color: #323232;
                border: 1px solid #444444;
                border-radius: 4px;
            }
            QCheckBox::indicator:checked { background-color: #27C93F; }
        """)
        
        self.config = []
        self.load_config()
        self.init_ui()
        self.refresh_list()


    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)
        
        # --- Left Panel ---
        left_panel = QWidget()
        left_panel.setObjectName("left_panel")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(['Name', 'Command'])
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        left_layout.addWidget(self.tree)
        
        btn_layout = QHBoxLayout()
        for text, slot in [("Add", self.add_program), ("Edit", self.edit_program), ("Remove", self.remove_program)]:
            btn = QPushButton(text)
            btn.clicked.connect(slot)
            btn_layout.addWidget(btn)
        left_layout.addLayout(btn_layout)
        
        # Launch Button (Big)
        launch_layout = QHBoxLayout()
        
        self.btn_launch = QPushButton("Launch Selected")
        self.btn_launch.clicked.connect(self.launch_selected)
        launch_layout.addWidget(self.btn_launch)
        
        self.btn_launch_all = QPushButton("Launch All")
        self.btn_launch_all.clicked.connect(self.launch_all)
        launch_layout.addWidget(self.btn_launch_all)
        
        left_layout.addLayout(launch_layout)
        
        splitter.addWidget(left_panel)
        
        # --- Right Panel (MDI Area) ---
        right_panel = QWidget()
        right_panel.setObjectName("right_panel")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        # MDI Controls
        mdi_controls = QHBoxLayout()
        btn_tile = QPushButton("Tile Windows")
        btn_tile.clicked.connect(self.tile_windows)
        mdi_controls.addWidget(btn_tile)
        
        btn_cascade = QPushButton("Cascade Windows")
        btn_cascade.clicked.connect(self.cascade_windows)
        mdi_controls.addWidget(btn_cascade)
        
        btn_close_all = QPushButton("Close All")
        btn_close_all.clicked.connect(self.close_all_windows)
        mdi_controls.addWidget(btn_close_all)
        
        mdi_controls.addStretch()
        right_layout.addLayout(mdi_controls)

        # MDI Area
        self.mdi = QMdiArea()
        self.mdi.setBackground(QBrush(QColor("#2d2d2d")))
        
        # Apply Fusion style ONLY to MDI area for custom title bars
        self.mdi.setStyle(QStyleFactory.create("Fusion"))
        
        # Set Dark Palette for MDI Area to ensure title bars are dark
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.black)
        dark_palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
        dark_palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
        
        # QPalette.Active and Inactive groups can be set if needed
        self.mdi.setPalette(dark_palette)

        self.mdi.setStyleSheet("""
            QMdiSubWindow {
                background-color: #2b2b2b;
                border: 1px solid #555555;
            }
            QMdiSubWindow::title {
                background-color: #3c3c3c;
                color: #ffffff;
                height: 28px;
                font-weight: bold;
                padding-left: 5px;
            }
            QMdiSubWindow::title:active {
                background-color: #4d4d4d;
                color: #ffffff;
            }
            QPushButton {
                background-color: #323232;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 5px 14px;
                font-weight: 500;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #404040;
                color: white;
            }
            QPushButton:pressed {
                background-color: #222222;
            }
        """)
        
        self.mdi.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.mdi.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        right_layout.addWidget(self.mdi)
        
        splitter.addWidget(right_panel)
        
        splitter.setSizes([300, 800])

    def setup_ipc_server(self):
        self.tcp_server = QTcpServer(self)
        if not self.tcp_server.listen(QHostAddress.SpecialAddress.LocalHost, 65432):
             print(f"Failed to start IPC Server: {self.tcp_server.errorString()}")
             return
        self.tcp_server.newConnection.connect(self.handle_ipc_connection)
        print(f"IPC Server listening on port 65432")

    def handle_ipc_connection(self):
        client_socket = self.tcp_server.nextPendingConnection()
        if not client_socket: return
        client_socket.readyRead.connect(lambda: self.read_ipc_data(client_socket))
        client_socket.disconnected.connect(client_socket.deleteLater)

    def read_ipc_data(self, socket):
        data = socket.readAll()
        if not data: return
        try:
            msg = json.loads(bytes(data).decode('utf-8'))
            action = msg.get('action')
            
            response = {"status": "error", "message": "Unknown action"}
            
            if action == 'start':
                # Create a temporary program config
                prog = {
                    'name': msg.get('name', 'Remote Process'),
                    'command': msg.get('command', ''),
                    'cwd': msg.get('cwd', os.getcwd()),
                    'shell': '/bin/zsh' 
                }
                
                # Launch it
                try:
                    terminal = self.launch_program(prog)
                    # Get log path
                    log_path = getattr(terminal, 'log_file_path', '')
                    # PID might not be ready immediately if using QProcess.start? 
                    # start_process in TerminalTab calls process.start then waitForStarted(1000)
                    # So pid should be available.
                    pid = 0
                    if terminal.process and terminal.process.state() != QProcess.ProcessState.NotRunning:
                         pid = terminal.process.processId()
                    
                    response = {
                        "status": "success",
                        "log_path": log_path,
                        "pid": pid
                    }
                except Exception as e:
                    response = {"status": "error", "message": str(e)}
            
            # Send response
            socket.write(json.dumps(response).encode('utf-8'))
            socket.flush()
            socket.disconnectFromHost()
            
        except Exception as e:
            print(f"IPC Error: {e}")
            socket.disconnectFromHost()

    def start_mcp_server(self):
        try:
            # Check if dependencies are installed (rudimentary check or just try to run)
            script_path = os.path.abspath(__file__)
            
            # Run with --sse flag
            # Use the same python interpreter as the current process
            python_exe = sys.executable
            
            # Use detached process with start_new_session to ensure it runs independently 
            # but we will kill it on exit.
            self.mcp_process = subprocess.Popen(
                [python_exe, script_path, "--mcp", "--sse"],
                cwd=os.path.dirname(script_path),
                stdout=subprocess.DEVNULL, # Or redirect to a log?
                stderr=subprocess.DEVNULL,
                start_new_session=True 
            )
            print(f"MCP Server started with PID: {self.mcp_process.pid} (SSE Mode, Port default 8000)")
            
        except Exception as e:
            print(f"Failed to start MCP Server: {e}")

    def closeEvent(self, event):
        # Clean up MCP server
        if self.mcp_process:
            print("Stopping MCP Server...")
            self.mcp_process.terminate()
            try:
                self.mcp_process.wait(timeout=2)
            except:
                self.mcp_process.kill()
        super().closeEvent(event)

    def load_config(self):
        if not os.path.exists(CONFIG_FILE):
            self.config = []
            return
        try:
            with open(CONFIG_FILE, 'r') as f:
                self.config = json.load(f)
        except json.JSONDecodeError:
            QMessageBox.critical(self, "Error", "Config file is not valid JSON.")
            self.config = []

    def save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=4, ensure_ascii=False)

    def refresh_list(self):
        self.tree.clear()
        for prog in self.config:
            item = QTreeWidgetItem([prog.get('name', ''), prog.get('command', '')])
            self.tree.addTopLevelItem(item)

    def add_program(self):
        dialog = EditDialog(self)
        if dialog.exec():
            self.config.append(dialog.get_data())
            self.save_config()
            self.refresh_list()

    def edit_program(self):
        selected = self.tree.selectedItems()
        if not selected: return
        idx = self.tree.indexOfTopLevelItem(selected[0])
        dialog = EditDialog(self, self.config[idx])
        if dialog.exec():
            self.config[idx] = dialog.get_data()
            self.save_config()
            self.refresh_list()

    def remove_program(self):
        selected = self.tree.selectedItems()
        if not selected: return
        idx = self.tree.indexOfTopLevelItem(selected[0])
        if QMessageBox.question(self, "Confirm", "Remove this program?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            del self.config[idx]
            self.save_config()
            self.refresh_list()

    def launch_program(self, prog):
        # Create new subwindow with Frameless hint for custom title bar
        sub = QMdiSubWindow()
        sub.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        
        # Container Widget
        container = QWidget()
        # Rounded corners for the container, matching background
        container.setStyleSheet("background-color: #1E1E1E; border-radius: 5px;")
        
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Custom Title Bar
        title_bar = CustomTitleBar(sub, prog.get('name', 'Unknown'))
        layout.addWidget(title_bar)
        
        # Terminal Content
        # Terminal Content
        terminal = TerminalTab(prog)
        # Remove border from terminal output, set background, and FORCE scrollbar style
        terminal.terminal_output.setStyleSheet("""
            QTextEdit { 
                background-color: #151515; 
                color: white; 
                border: none; 
                font-family: 'Menlo', 'Courier New', monospace; 
            }
            QScrollBar:vertical {
                border: none;
                background: #151515;
                width: 12px;
                margin: 0px 0px 0px 0px;
            }
            QScrollBar::handle:vertical {
                background: #424242;
                min-height: 20px;
                border-radius: 6px;
                margin: 2px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
        """)
        
        layout.addWidget(terminal)
        
        sub.setWidget(container)
        sub.resize(600, 400)
        
        self.mdi.addSubWindow(sub)
        sub.show()
        
        return terminal
        
        # When subwindow closes, ensure process is stopped if possible.
        # However, QMdiSubWindow doesn't emit closed signal easily with widget access.
        # We can hooking closeEvent of TerminalTab/Widget if needed, 
        # but for now rely on user stopping or app exit.
        # Or better: make TerminalTab handle its own cleanup on delete.
        
        # Auto tile if requested? No, user manual action.

    def launch_selected(self):
        selected = self.tree.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Warning", "No program selected.")
            return
        
        idx = self.tree.indexOfTopLevelItem(selected[0])
        prog = self.config[idx]
        self.launch_program(prog)

    def launch_all(self):
        if not self.config:
            QMessageBox.information(self, "Info", "No programs to launch.")
            return
        
        for prog in self.config:
            self.launch_program(prog)
            
        self.tile_windows()

    def tile_windows(self):
        self.mdi.tileSubWindows()

    def cascade_windows(self):
        self.mdi.cascadeSubWindows()

    def close_all_windows(self):
        self.mdi.closeAllSubWindows()


class EditDialog(QDialog):
    def __init__(self, parent=None, data=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Program" if data else "Add Program")
        self.setModal(True)
        self.resize(500, 200)
        self.data = data
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("Name:"))
        self.name_edit = QLineEdit()
        layout.addWidget(self.name_edit)
        
        layout.addWidget(QLabel("Command:"))
        self.cmd_edit = QLineEdit()
        layout.addWidget(self.cmd_edit)
        
        layout.addWidget(QLabel("Working Directory:"))
        cwd_layout = QHBoxLayout()
        self.cwd_edit = QLineEdit()
        cwd_layout.addWidget(self.cwd_edit)
        
        btn_browse = QPushButton("Browse")
        btn_browse.clicked.connect(self.browse_dir)
        cwd_layout.addWidget(btn_browse)
        layout.addLayout(cwd_layout)
        # Shell Selection
        layout.addWidget(QLabel("Shell:"))
        self.shell_combo = QComboBox()
        self.shell_combo.addItems(["/bin/zsh", "/bin/bash", "/bin/sh"])
        self.shell_combo.setEditable(True) # Allow custom shell
        layout.addWidget(self.shell_combo)
        
        if self.data:
            self.name_edit.setText(self.data.get('name', ''))
            self.cmd_edit.setText(self.data.get('command', ''))
            self.cwd_edit.setText(self.data.get('cwd', ''))
            shell = self.data.get('shell', '/bin/zsh')
            self.shell_combo.setCurrentText(shell)
        else:
            self.cwd_edit.setText(os.getcwd())
            self.shell_combo.setCurrentText("/bin/zsh")
            
        btn_layout = QHBoxLayout()
        btn_save = QPushButton("Save")
        btn_save.clicked.connect(self.validate_and_save)
        btn_layout.addWidget(btn_save)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(btn_cancel)
        
        layout.addLayout(btn_layout)

    def browse_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Select Directory", self.cwd_edit.text() or os.getcwd())
        if d: self.cwd_edit.setText(d)

    def validate_and_save(self):
        if not self.name_edit.text().strip() or not self.cmd_edit.text().strip():
            QMessageBox.warning(self, "Error", "Name and Command are required.")
            return
        self.accept()

    def get_data(self):
        return {
            'name': self.name_edit.text().strip(),
            'command': self.cmd_edit.text().strip(),
            'cwd': self.cwd_edit.text().strip(),
            'shell': self.shell_combo.currentText().strip()
        }



# --- MCP Tools ---

@mcp.tool()
def list_programs() -> str:
    """Lists all configured programs available to run."""
    config = pm.get_config()
    if not config:
        return "No programs configured."
    
    result = []
    # Include dynamic ones
    statuses = pm.get_all_statuses()
    
    # Merge config and dynamic
    # pm.get_all_statuses() returns dict name -> status
    
    for name, status in statuses.items():
        # Find config if exists
        cmd = "Dynamic"
        cwd = ""
        for p in config:
            if p['name'] == name:
                cmd = p['command']
                cwd = p['cwd']
                break
        
        status_str = f"[{status['status']}]"
        if status['status'] == 'Running':
            status_str += f" (PID: {status['pid']}, CPU: {status['cpu_percent']}%, Mem: {status['memory_mb']:.1f}MB)"
        
        result.append(f"- {name}: {status_str}\n  Command: {cmd}")
    
    return "\n".join(result)

@mcp.tool()
def start_program(name: str) -> str:
    """Starts a specific program by name."""
    # Try GUI first if it's in config
    prog = pm.get_program_info(name)
    if prog:
        gui_resp = try_gui_execution(prog['command'], name, prog.get('cwd', '.'))
        if gui_resp:
            pid = gui_resp.get('pid')
            log_path = gui_resp.get('log_path')
            pm.register_external_process(name, pid, log_path)
            return f"Started {name} (via GUI, PID: {pid})"

    try:
        return pm.start_process(name)
    except Exception as e:
        return f"Error starting {name}: {str(e)}"

@mcp.tool()
def run_terminal_command(command: str, name: str = None, cwd: str = ".") -> str:
    """Runs an arbitrary terminal command.
    
    Args:
        command: The shell command to execute.
        name: Optional name for the process (for stopping/logging). If not provided, a unique name is generated.
        cwd: Working directory (defaults to current).
    
    Returns:
        Status message including the process name.
    """
    if not name:
        name = f"cmd_{int(time.time())}"
        
    # Try GUI first
    gui_resp = try_gui_execution(command, name, cwd)
    if gui_resp:
        # Register with PM so we can track logs
        pid = gui_resp.get('pid')
        log_path = gui_resp.get('log_path')
        pm.register_external_process(name, pid, log_path)
        return f"Started {name} (via GUI, PID: {pid})"
        
    try:
        return pm.start_dynamic_process(command, name, cwd)
    except Exception as e:
        return f"Error running command: {str(e)}"

@mcp.tool()
def stop_program(name: str) -> str:
    """Stops a running program by name."""
    try:
        return pm.stop_process(name)
    except Exception as e:
        return f"Error stopping {name}: {str(e)}"

@mcp.tool()
def restart_program(name: str) -> str:
    """Restarts a program by name."""
    try:
        try:
            pm.stop_process(name)
        except:
            pass # Ignore if not running
        return pm.start_process(name)
    except Exception as e:
        return f"Error restarting {name}: {str(e)}"

@mcp.tool()
def get_program_logs(name: str, lines: int = 50) -> str:
    """Gets the recent logs (stdout/stderr) for a running program (configured or dynamic)."""
    return pm.get_logs(name, lines)

@mcp.tool()
def send_program_input(name: str, input_text: str) -> str:
    """Sends text input (stdin) to a running program."""
    try:
        pm.write_input(name, input_text)
        return f"Sent input to {name}"
    except Exception as e:
        return f"Error sending input: {str(e)}"

@mcp.tool()
def add_program_config(name: str, command: str, cwd: str = ".") -> str:
    """Adds a new program to the configuration."""
    config = pm.get_config()
    # Check if exists
    for prog in config:
        if prog['name'] == name:
            return f"Error: Program '{name}' already exists."
    
    new_prog = {
        "name": name,
        "command": command,
        "cwd": cwd,
        "shell": "/bin/zsh" 
    }
    config.append(new_prog)
    
    # Save (reusing the logic from launcher if possible, but pm loads separate)
    # pm doesn't have a save method exposed, let's implement simple save here based on pm's loaded config
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        pm.load_config() # Reload
        return f"Added program '{name}'."
    except Exception as e:
        return f"Error saving config: {str(e)}"

@mcp.tool()
def remove_program_config(name: str) -> str:
    """Removes a program from the configuration."""
    config = pm.get_config()
    new_config = [p for p in config if p['name'] != name]
    
    if len(new_config) == len(config):
        return f"Program '{name}' not found."
    
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(new_config, f, indent=4)
        pm.load_config()
        return f"Removed program '{name}'."
    except Exception as e:
        return f"Error saving config: {str(e)}"

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    if "--mcp" in sys.argv:
        if "--sse" in sys.argv:
            mcp.run(transport="sse")
        else:
            mcp.run()
    else:
        app = QApplication(sys.argv)
        app.setWindowIcon(QIcon('app_icon.png'))
        window = LauncherApp()
        window.show()
        try:
            sys.exit(app.exec())
        except KeyboardInterrupt:
            sys.exit(0)
