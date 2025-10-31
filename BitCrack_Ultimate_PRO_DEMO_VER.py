# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# BitCrack Ultimate PRO DEMO VER
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# استاندارد و تمیز برای PyQt6
import os, sys, time, json, math, re, sqlite3, shutil, threading, subprocess, collections, random
from datetime import datetime
from decimal import Decimal, getcontext
import csv
import psutil

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QGuiApplication  
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QGroupBox,
    QSpinBox,
    QComboBox,
    QTextEdit,
    QCheckBox,
    QFileDialog,
    QMessageBox,
    QDialog,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QFrame,
    QTabWidget,
    QScrollArea,
    QSplitter,
    QSizePolicy,
)

# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
#       FILES PATH
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

INPUT_FILE_DEFAULT    = "btc.txt"
getcontext().prec = 200

try:
    import pynvml
    _HAS_NVML = True
except Exception:
    _HAS_NVML = False

ADDR_RE = re.compile(r'\b((bc1[0-9a-z]{11,71})|([13][a-km-zA-HJ-NP-Z1-9]{25,34}))\b', re.I)
WIF_RE = re.compile(r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b')  # کلید خصوصی WIF

def clamp(v, lo, hi): return max(lo, min(hi, v))
def hex64(h): return h.rjust(64, '0')  # pad to 64 hex chars for keyspace

#&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
# FoundViewerDialog
#&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&  
class FoundViewerDialog(QDialog):
    def __init__(self, db_path: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Found Keys (DB Viewer)")
        self.resize(960, 560)
        self.db_path = db_path
        self.limit = 2000  # برای سبک موندن

        v = QVBoxLayout(self)

        # نوار بالا
        top = QHBoxLayout()
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("جستجو در address/privkey ...")
        btn_refresh = QPushButton("Refresh")
        btn_copy    = QPushButton("Copy Selected")
        btn_csv     = QPushButton("Export CSV (selected/all)")

        btn_refresh.clicked.connect(self.reload)
        btn_copy.clicked.connect(self.copy_selected)
        btn_csv.clicked.connect(self.export_csv)
        self.search_box.textChanged.connect(self.reload)

        top.addWidget(QLabel("Filter:"))
        top.addWidget(self.search_box, 1)
        top.addWidget(btn_refresh)
        top.addWidget(btn_copy)
        top.addWidget(btn_csv)
        v.addLayout(top)

        # جدول
        self.table = QTableWidget(0, 5, self)
        self.table.setHorizontalHeaderLabels(["id","part_index","address","privkey","timestamp"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.table.verticalHeader().setVisible(False)
        hdr = self.table.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        v.addWidget(self.table, 1)

        self.reload()
#=====================================================================================
#============================ TIME EXPR=======================================================
    def _time_expr(self, c) -> str:
        cols = [r[1].lower() for r in c.execute("PRAGMA table_info(found_keys)")]
        if "ts" in cols and "timestamp" in cols:
            return "COALESCE(ts, timestamp, datetime('now')) AS ts"
        elif "ts" in cols:
            return "ts AS ts"
        elif "timestamp" in cols:
            return "timestamp AS ts"
        elif "created_at" in cols:
            return "created_at AS ts"
        else:
            return "datetime('now') AS ts"
#=================================================================================
#================================= DEF RELOAD ===================================
    def reload(self):
        filt = (self.search_box.text() or "").strip()
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            texpr = self._time_expr(c)

            sql = f"SELECT id, part_index, address, privkey, {texpr} FROM found_keys"
            params = []
            if filt:
                sql += " WHERE address LIKE ? OR privkey LIKE ?"
                q = f"%{filt}%"
                params.extend([q, q])
            sql += " ORDER BY id DESC"
            sql += f" LIMIT {int(self.limit)}"

            rows = c.execute(sql, params).fetchall()
            conn.close()

            self.table.setRowCount(len(rows))
            for r, (id_, p, a, k, ts) in enumerate(rows):
                vals = [id_, p, a, k, ts]
                for ci, val in enumerate(vals):
                    it = QTableWidgetItem("" if val is None else str(val))
                    if ci in (0,1):
                        it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    self.table.setItem(r, ci, it)
        except Exception as ex:
            try:
                if self.parent(): self.parent()._err(f"FoundViewerDialog.reload: {ex}")
            except Exception:
                print("FoundViewerDialog.reload:", ex)
#==================================================================================================
#=================================COPY SELECTED ====================================================
    def copy_selected(self):
        sel = self.table.selectedItems()
        if not sel:
            return
        rows = sorted(set(it.row() for it in sel))
        lines = []
        for r in rows:
            vals = [self.table.item(r, c).text() if self.table.item(r, c) else "" for c in range(5)]
            lines.append(",".join(vals))
        QGuiApplication.clipboard().setText("\n".join(lines))
#=====================================================================================
#================================EXPORT CSV =====================================================
    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "found_view.csv", "CSV (*.csv)")
        if not path:
            return
        try:
            sel_rows = sorted(set(it.row() for it in self.table.selectedItems()))
            itr = sel_rows if sel_rows else range(self.table.rowCount())
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["id","part_index","address","privkey","timestamp"])
                for r in itr:
                    vals = [self.table.item(r, c).text() if self.table.item(r, c) else "" for c in range(5)]
                    w.writerow(vals)
        except Exception as ex:
            try:
                if self.parent(): self.parent()._err(f"FoundViewerDialog.export_csv: {ex}")
            except Exception:
                print("FoundViewerDialog.export_csv:", ex)
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
#%%%                GUI Q MAIN WINDOW / INIT / SUPER INIT
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
class BitcrackGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        # مسیر پایه پروژه
        self.base_dir = os.path.abspath(os.path.dirname(__file__))

        # مسیر دیتابیس پروفایل‌ها
        db_folder = os.path.join(self.base_dir, "db")
        os.makedirs(db_folder, exist_ok=True)
        self.db_path = os.path.join(db_folder, "profiles.sqlite")
        #====================================================================================
        self.setWindowTitle("BitCrack Ultimate DEMO ✅")
        self.resize(1200, 850)
        self.setMinimumSize(1000, 700)

        
        # ====================== Tabs ==========================
        tabs = QTabWidget()
        tabs.setDocumentMode(True)
        tabs.setTabPosition(QTabWidget.TabPosition.North)
        tabs.setMovable(True)

        # ---------- Helper to create a scrollable tab ----------
        def make_scroll_tab(widget: QWidget, name: str):
            container = QWidget()
            layout = QVBoxLayout(container)
            layout.setContentsMargins(8, 8, 8, 8)
            layout.setSpacing(12)
            layout.addWidget(widget)
            layout.addStretch(1)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(container)
            tabs.addTab(scroll, name)

        # ================== Tab 1: Keyspace / Subrange / HEX ==================
        tab1_widget = QWidget()
        tab1_layout = QVBoxLayout(tab1_widget)
        tab1_layout.setSpacing(15)

        # GroupBox: Keyspace Settings
        gb_keyspace = QGroupBox("Keyspace Settings")
        gb_keyspace_layout = QVBoxLayout()
        gb_keyspace_layout.setSpacing(8)
        gb_keyspace_layout.addWidget(getattr(self, "_ui_keyspace", lambda: QLabel("Keyspace UI"))())
        gb_keyspace.setLayout(gb_keyspace_layout)
        tab1_layout.addWidget(gb_keyspace)

        # GroupBox: Subrange Settings
        gb_subrange = QGroupBox("Subrange Settings")
        gb_subrange_layout = QVBoxLayout()
        gb_subrange_layout.setSpacing(8)
        gb_subrange_layout.addWidget(getattr(self, "_ui_subrange", lambda: QLabel("Subrange UI"))())
        gb_subrange.setLayout(gb_subrange_layout)
        tab1_layout.addWidget(gb_subrange)

        # GroupBox: Range / HEX
        gb_range = QGroupBox("Range / HEX")
        gb_range_layout = QVBoxLayout()
        gb_range_layout.setSpacing(8)
        gb_range_layout.addWidget(getattr(self, "_ui_range_hex", lambda: QLabel("Range HEX UI"))())
        gb_range.setLayout(gb_range_layout)
        tab1_layout.addWidget(gb_range)

        tab1_layout.addStretch(1)
        make_scroll_tab(tab1_widget, "Keyspace / Subrange / HEX")

        # ================== Tab 2: GPU / Input / Targets ==================
        tab2_widget = QWidget()
        tab2_layout = QVBoxLayout(tab2_widget)
        tab2_layout.setSpacing(15)

        gb_gpu = QGroupBox("GPU Manager")
        gb_gpu_layout = QVBoxLayout()
        gb_gpu_layout.setSpacing(8)
        gb_gpu_layout.addWidget(getattr(self, "_ui_gpu", lambda: QLabel("GPU UI"))())
        gb_gpu.setLayout(gb_gpu_layout)
        tab2_layout.addWidget(gb_gpu)

        gb_input = QGroupBox("Input / Output")
        gb_input_layout = QVBoxLayout()
        gb_input_layout.setSpacing(8)
        gb_input_layout.addWidget(getattr(self, "_ui_input_file", lambda: QLabel("Input UI"))())
        gb_input.setLayout(gb_input_layout)
        tab2_layout.addWidget(gb_input)

        gb_targets = QGroupBox("Targets")
        gb_targets_layout = QVBoxLayout()
        gb_targets_layout.setSpacing(8)
        gb_targets_layout.addWidget(getattr(self, "_ui_target_manager", lambda: QLabel("Targets UI"))())
        gb_targets.setLayout(gb_targets_layout)
        tab2_layout.addWidget(gb_targets)

        tab2_layout.addStretch(1)
        make_scroll_tab(tab2_widget, "GPU / Input / Targets")

        # ================== Tab 3: Live Status / Progress ==================
        tab3_widget = QWidget()
        tab3_layout = QVBoxLayout(tab3_widget)
        tab3_layout.setSpacing(15)

        gb_live = QGroupBox("Live Status")
        gb_live_layout = QVBoxLayout()
        gb_live_layout.setSpacing(8)
        gb_live_layout.addWidget(getattr(self, "_ui_live_status", lambda: QLabel("Live Status UI"))())
        gb_live.setLayout(gb_live_layout)
        tab3_layout.addWidget(gb_live)

        gb_progress = QGroupBox("Progress")
        gb_progress_layout = QVBoxLayout()
        gb_progress_layout.setSpacing(8)
        gb_progress_layout.addWidget(getattr(self, "_ui_progress", lambda: QLabel("Progress UI"))())
        gb_progress.setLayout(gb_progress_layout)
        tab3_layout.addWidget(gb_progress)

        tab3_layout.addStretch(1)
        make_scroll_tab(tab3_widget, "Live Status / Progress")

        # ================== Controls + Footer ==================
        controls_widget = QWidget()
        controls_layout = QVBoxLayout(controls_widget)
        try:
            controls_layout.addLayout(getattr(self, "_ui_controls", lambda: QVBoxLayout())())
        except Exception:
            controls_layout.addWidget(QWidget())
        controls_layout.addStretch(1)

        foot = QLabel("© Mr-Danesh | 2025–2026")
        foot.setAlignment(Qt.AlignmentFlag.AlignCenter)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(tabs)
        splitter.addWidget(controls_widget)
        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 1)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(6, 6, 6, 6)
        main_layout.setSpacing(6)
        main_layout.addWidget(splitter)
        main_layout.addWidget(foot)

        scroll_main = QScrollArea()
        scroll_main.setWidgetResizable(True)
        inner = QWidget()
        inner.setLayout(main_layout)
        scroll_main.setWidget(inner)

        container = QWidget()
        hl = QHBoxLayout(container)
        hl.setContentsMargins(0, 0, 0, 0)
        hl.addWidget(scroll_main)
        self.setCentralWidget(container)

        # ================== Dark Theme ==================
        self.setStyleSheet("""
            QMainWindow {
                background-color: #fafafa;
                color: #222;
            }

            QLabel {
                color: #222;
                font-size: 13px;
            }

            QLineEdit, QSpinBox, QComboBox, QTextEdit, QPlainTextEdit {
                background-color: #ffffff;
                color: #222;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 4px;
                selection-background-color: #cce5ff;
                selection-color: #000;
            }

            QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QTextEdit:focus {
                border: 1px solid #448aff;
                background-color: #ffffff;
            }

            QPushButton {
                background-color: #e9e9e9;
                color: #111;
                border: 1px solid #bbb;
                border-radius: 6px;
                padding: 5px 10px;
            }

            QPushButton:hover {
                background-color: #f2f2f2;
                border: 1px solid #999;
            }

            QPushButton:pressed {
                background-color: #dcdcdc;
                border: 1px solid #888;
            }

            QTabWidget::pane {
                border: 1px solid #cccccc;
                background-color: #fdfdfd;
            }

            QTabBar::tab {
                background: #f4f4f4;
                border: 1px solid #cccccc;
                border-bottom: none;
                padding: 6px 12px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }

            QTabBar::tab:selected {
                background: #ffffff;
                border-color: #bbbbbb;
                font-weight: bold;
            }

            QTableWidget {
                background-color: #ffffff;
                gridline-color: #ccc;
                color: #222;
                selection-background-color: #cce5ff;
                selection-color: #000;
            }

            QHeaderView::section {
                background-color: #f2f2f2;
                color: #222;
                border: 1px solid #ccc;
                padding: 4px;
            }

            QScrollArea {
                background-color: #fafafa;
            }

            QCheckBox {
                spacing: 6px;
                color: #222;
            }

            QComboBox QAbstractItemView {
                background-color: #ffffff;
                selection-background-color: #cce5ff;
                selection-color: #000;
                border: 1px solid #aaa;
            }

            QSplitter::handle {
                background-color: #dddddd;
                width: 4px;
            }

            QProgressBar {
                border: 1px solid #ccc;
                border-radius: 5px;
                text-align: center;
                background-color: #f3f3f3;
            }

            QProgressBar::chunk {
                background-color: #4a90e2;
                width: 10px;
                margin: 0.5px;
            }
        """)

#==========================================================================
## --- helpers: زمان به HH:MM:SS و MM:SS
#==========================================================================
    def _sec_to_hms(self, sec: float) -> str:
        try:
            sec = max(0, int(sec))
            h = sec // 3600
            m = (sec % 3600) // 60
            s = sec % 60
            return f"{h:02d}:{m:02d}:{s:02d}"
        except Exception:
            return "00:00:00"
#==========================================================================
#       SEC TO MMSS
#==========================================================================
    def _sec_to_mmss(self, sec: float) -> str:
        try:
            sec = max(0, int(sec))
            m = sec // 60
            s = sec % 60
            return f"{m:02d}:{s:02d}"
        except Exception:
            return "00:00"
        
#=========================================================================
#   TRY FLUSH PENDING FOUND
#========================================================================
    def _try_flush_pending_found(self, part_idx: int):
        """اگر آدرس و پرایوت‌کی هر دو آماده‌اند، Found را (فقط در صورت غیرتکراری بودن) ثبت می‌کند و UI/DB را آپدیت می‌کند."""
        if not (getattr(self, "_pending_addr", None) and getattr(self, "_pending_pk", None)):
            return

        addr = self._pending_addr
        pk   = self._pending_pk
        # پاک‌کردن حالت (تا دوبار ثبت نشود)
        self._pending_addr = None
        self._pending_pk   = None

        inserted = False
        try:
            # نسخهٔ جدید _save_found باید True/False برگرداند
            res = self._save_found(part_idx, addr, pk)
            inserted = bool(res) if (res is not None) else False

            # اگر نسخهٔ قدیمی _save_found چیزی برنگرداند، fallback: وجود رکورد را چک کن
            if res is None:
                try:
                    conn = sqlite3.connect(self.db_path); c = conn.cursor()
                    c.execute("SELECT 1 FROM found_keys WHERE address=? AND privkey=? LIMIT 1", (addr, pk))
                    exists = (c.fetchone() is not None)
                    conn.close()
                    inserted = not exists
                except Exception:
                    # اگر نتوانستیم چک کنیم، فرض را بر درج می‌گذاریم تا از دست نرود
                    inserted = True
        except Exception as ex:
            self._err(f"_try_flush_pending_found/_save_found: {ex}")
            inserted = False

        if inserted:
            # فقط اگر جدید بود، شمارنده‌ها زیاد شوند
            self.part_keys += 1
            self.total_keys += 1

            # UI فوری
            if hasattr(self, "lbl_total_keys"):
                self.lbl_total_keys.setText(f"🔐 TOTAL FOUND: {self.total_keys:,}")
            if hasattr(self, "lbl_found"):
                cnt = self._found_count()
                self.lbl_found.setText(f"🔎 FOUND COUNT: {int(cnt):,}")
            self._append_log_line(f"🔑 Found [Part {part_idx}] {addr} | {pk}", "FOUND")
        else:
            # تکراری: شمارنده زیاد نکن، فقط اطلاع بده
            self._append_log_line(f"🟡 Duplicate found skipped [Part {part_idx}] {addr}", "WARN")

#==========================================================================
#   FOUND COUNT
#==========================================================================
    def _found_count(self) -> int:
        """اولویت: progress.found_count → شمارش found_keys → fallback به self.total_keys"""
        try:
            if not self.db_path or not os.path.exists(self.db_path):
                return int(getattr(self, "total_keys", 0))

            conn = sqlite3.connect(self.db_path); c = conn.cursor()

            # 1) از progress بخوان
            fc = 0
            try:
                c.execute("SELECT found_count FROM progress WHERE id=1")
                row = c.fetchone()
                if row and row[0] is not None:
                    fc = int(row[0] or 0)
            except sqlite3.OperationalError:
                fc = 0

            # 2) اگر 0 بود، از جدول found_keys بشمار
            if fc == 0:
                try:
                    c.execute("SELECT COUNT(1) FROM found_keys")
                    row = c.fetchone()
                    if row and row[0] is not None:
                        fc = int(row[0] or 0)
                except sqlite3.OperationalError:
                    pass

            conn.close()

            # 3) همچنان 0؟ از رم بخوان
            if fc <= 0:
                fc = int(getattr(self, "total_keys", 0))
            return fc

        except Exception:
            return int(getattr(self, "total_keys", 0))
#===================================================================================
#               EXTERACT FOUND FROM LINE
#===================================================================================
    def _extract_found_from_line(self, line: str):
        """هر جا 'آدرس معتبر' + 'کلید خصوصی (hex64 یا WIF)' دیدیم → Found."""
        if not line:
            return None, None
        addr = None
        pk = None

        m_addr = ADDR_RE.search(line)
        if m_addr:
            addr = m_addr.group(1)

        # اول سعی کن hex64
        m_hex = re.search(r'\b[0-9A-Fa-f]{64}\b', line)
        if m_hex:
            pk = m_hex.gro=up(0)
        else:
            # اگر hex نبود، شاید WIF باشد
            m_wif = WIF_RE.search(line)
            if m_wif:
                pk = m_wif.group(0)

        return (addr, pk) if (addr and pk) else (None, None)
#===================================================================================
#       ENSURE PROGRESS SCHEMA
#===================================================================================
    def _ensure_progress_schema(self):
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()

            # اگر progress نبود، بساز (حداقل ستون‌ها)
            c.execute("""
                CREATE TABLE IF NOT EXISTS progress (
                    id INTEGER PRIMARY KEY,
                    last_part INTEGER DEFAULT 0,
                    elapsed_seconds REAL DEFAULT 0,
                    total_keys INTEGER DEFAULT 0,
                    loop_count INTEGER DEFAULT 0,
                    max_loops INTEGER DEFAULT 0,
                    found_count INTEGER DEFAULT 0,
                    processed_total REAL DEFAULT 0,
                    start_loop INTEGER DEFAULT 1,
                    random_parts_done INTEGER DEFAULT 0
                )
            """)

            # ستون‌های جدید/لازم را در صورت نبود اضافه کن
            for col, ddl in [
                ("tested_total",           "ALTER TABLE progress ADD COLUMN tested_total INTEGER DEFAULT 0"),
                ("elapsed_total_seconds",  "ALTER TABLE progress ADD COLUMN elapsed_total_seconds REAL DEFAULT 0"),
                ("updated_at",             "ALTER TABLE progress ADD COLUMN updated_at TEXT"),
                ("start_loop",             "ALTER TABLE progress ADD COLUMN start_loop INTEGER DEFAULT 1"),
                ("random_parts_done",      "ALTER TABLE progress ADD COLUMN random_parts_done INTEGER DEFAULT 0"),
            ]:
                try:
                    c.execute(f"SELECT {col} FROM progress LIMIT 1")
                except sqlite3.OperationalError:
                    c.execute(ddl)

            # ردیف 1 همیشه وجود داشته باشد
            c.execute("INSERT OR IGNORE INTO progress (id) VALUES (1)")

            # بررسی ستون جدید custom_parts_json
            try:
                c.execute("SELECT custom_parts_json FROM progress LIMIT 1")
            except Exception:
                try:
                    c.execute("ALTER TABLE progress ADD COLUMN custom_parts_json TEXT")
                except Exception:
                    pass

            # ✅ commit و بستن ارتباط درون try، نه بیرون
            conn.commit()

        except Exception as ex:
            self._err(f"_ensure_progress_schema: {ex}")

        finally:
            # حتی در صورت خطا، اتصال بسته شود
            try:
                if 'conn' in locals() and conn:
                    conn.close()
            except Exception:
                pass

#===============================================================================
#       LOAD PROGRESS
#================================================================================
    def _load_progress(self):
        if not self.db_path or not os.path.exists(self.db_path):
            return
        try:
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            c.execute("""SELECT last_part, elapsed_seconds, total_keys, loop_count, 
                                max_loops, found_count, processed_total, start_loop, random_parts_done
                        FROM progress WHERE id=1""")
            row = c.fetchone()
            conn.close()
            if not row:
                self.current_part = 0
                self.elapsed_total_seconds_before = 0.0
                self.total_keys = 0
                self.loop_count = 0
                self.max_loops = 0
                self.total_part_key = 0
                self.start_loop = 1   # 🔹 مقدار پیش‌فرض
                self._random_parts_done = 0  # 🔹 شمارنده رندوم پیش‌فرض
                return

            (last_part, elapsed_sec, total_keys, loop_count,
             max_loops, _found_count, processed_total, start_loop, rnd_done) = row

            self.current_part = int(last_part or 0)
            self.elapsed_total_seconds_before = float(elapsed_sec or 0.0)
            self.total_keys = int(total_keys or 0)
            self.loop_count = int(loop_count or 0)
            self.max_loops = int(max_loops or 0)
            self.start_loop = int(start_loop or 1)   # 🔹 اضافه شد
            self._random_parts_done = int(rnd_done or 0)  # 🔹 شمارنده رندوم بازیابی شد

            # baseline ها
            if not hasattr(self, "part_key_current"): self.part_key_current = 0
            if not hasattr(self, "tested_total"): self.tested_total = 0
            if not hasattr(self, "tested_baseline_session"): self.tested_baseline_session = 0
            if not hasattr(self, "tested_baseline_part"): self.tested_baseline_part = 0

            self.total_part_key = float(processed_total or 0.0)

        except Exception as ex:
            self._err(f"_load_progress: {ex}")

# ==========================================================================
#       HELPERS -----   UPDATE RANGE HEX
#==========================================================================     
    def _update_range_hex(self):
        try:
            s = int(self.start_bit.text())
            e = int(self.end_bit.text())
    
            if not (1 <= s <= e <= 256):
                self.start_hex.setText("Invalid")
                self.end_hex.setText("Invalid")
                return
    
            start_int = 1 << (s - 1)
    
            # حالت تک بیت → مثل بازه کامل محاسبه بشه
            end_int = (1 << e) - 1
    
            s_hex = f"{start_int:X}"
            e_hex = f"{end_int:X}"
    
            # نمایش 64 کاراکتری برای سازگاری با keyspace
            self.start_hex.setText(hex64(s_hex))
            self.end_hex.setText(hex64(e_hex))
    
        except Exception:
            self.start_hex.setText("Invalid")
            self.end_hex.setText("Invalid")
#===========================================================================
#
#========================================================================
    def _on_time_changed(self, value):
        """
        مدیریت تغییر مقدار زمان پارت (Time per Part) از SpinBox یا Slider
        """
        try:
            self._time_per_part_minutes = int(value)
            self._log(f"⏱ Time per part changed: {self._time_per_part_minutes} minutes")
        except Exception as ex:
            self._err(f"_on_time_changed: {ex}")

#==========================================================================
#           DETECT GPUS TO UI
#==========================================================================
    def _detect_gpus_to_ui(self):
        self.gpu_box.clear()
        try:
            out = subprocess.check_output(["nvidia-smi", "--query-gpu=index,name", "--format=csv,noheader"], text=True).strip().splitlines()
            for line in out: self.gpu_box.addItem(line.strip())
        except Exception:
            self.gpu_box.addItem("No NVIDIA GPU detected")
#==========================================================================
#   REFRESH COUNTRES UI
#==========================================================================
    def _refresh_counters_ui(self):
        try:
            # زمان‌ها (بدون تغییر)
            part_elapsed = 0
            if getattr(self, "start_part_time", None):
                part_elapsed = time.time() - float(self.start_part_time or 0)
            total_elapsed = float(getattr(self, "elapsed_total_seconds_before", 0.0) or 0.0)
            if getattr(self, "scanning", False) and getattr(self, "start_range_time", None):
                total_elapsed += (time.time() - float(self.start_range_time or 0))

            if hasattr(self, "lbl_time_part"):
                self.lbl_time_part.setText(f"⏱ TIME (PART) : {self._sec_to_mmss(part_elapsed)}")
            if hasattr(self, "lbl_time_total"):
                self.lbl_time_total.setText(f"🕰 TOTAL TIME : {self._sec_to_hms(total_elapsed)}")

            # پارت/لوپ
            total_parts = int(self.parts_spin.value()) if hasattr(self, "parts_spin") else 0
            if hasattr(self, "lbl_part_no"):
                self.lbl_part_no.setText(f"🔢 PART #: {int(getattr(self, 'current_part', 0))}/{total_parts}")

            max_loops = getattr(self, "max_loops", 0) or (self.max_loops_spin.value() if hasattr(self, "max_loops_spin") else 0)
            loops_now = int(getattr(self, "loop_count", 0))
            start_loop = int(getattr(self, "start_loop", 1))   # 🔹 مقدار ذخیره‌شده یا پیش‌فرض
            real_loop = start_loop + loops_now - 1             # -1 چون loop_count از 1 شروع می‌شه

            if hasattr(self, "lbl_loops"):
                self.lbl_loops.setText(f"🔁 LOOPS: {real_loop} / {('∞' if not max_loops else max_loops)}")

            # بقیه شمارنده‌ها (بدون تغییر) ...
            if hasattr(self, "lbl_targets"):
                self.lbl_targets.setText(f"🎯 TARGETS: {int(getattr(self, 'targets_count', 0)):,}")
            if hasattr(self, "lbl_gpu_line"):
                self.lbl_gpu_line.setText(f"🟢 GPU: {getattr(self, 'gpu_line', '—') or '—'}")

            if hasattr(self, "lbl_part_keys"):
                pk_delta = int(getattr(self, "part_key_current", 0) or 0)
                self.lbl_part_keys.setText(f"🗝 PART KEY: {pk_delta:,}")

            if hasattr(self, "lbl_total_keys"):
                self.lbl_total_keys.setText(f"🔐 TOTAL FOUND: {int(getattr(self, 'total_keys', 0)):,}")

            if hasattr(self, "lbl_found"):
                self.lbl_found.setText(f"🔎 FOUND COUNT: {int(self._found_count()):,}")

            if hasattr(self, "lbl_tested"):
                session_live_total = int(getattr(self, "total_part_key", 0) or 0) + int(getattr(self, "part_key_current", 0) or 0)
                self.lbl_tested.setText(f"🧮 TESTED TOTAL: {session_live_total:,}")

        except Exception as ex:
            self._err(f"_refresh_counters_ui: {ex}")

#===================================================================
#           SYNC RANDOM AUTO 
#=====================================================================
    def _set_checked_safely(self, w, checked: bool):
        """
        ایمن چک کردن یا آنچک کردن یک ویجت (CheckBox یا Button)
        بدون ایجاد سیگنال‌های اضافی یا خطا
        """
        if w is None:
            return
        try:
            bs = w.blockSignals(True)
            w.setChecked(bool(checked))
            w.blockSignals(bs)
        except Exception:
            pass
    
    
    def _sync_random_auto(self, *_):
        """
        هماهنگ‌سازی وضعیت Random و Auto بین UI و فلگ‌های داخلی
        این تابع ایمن است و می‌تواند هر زمان صدا زده شود.
        """
        try:
            # --- مدیریت Random ---
            val = False
            if hasattr(self, "chk_random") and self.chk_random is not None:
                try:
                    val = self.chk_random.isChecked()
                except Exception:
                    pass
    
            if hasattr(self, "btn_random") and self.btn_random is not None:
                try:
                    val = val or self.btn_random.isChecked()
                except Exception:
                    pass
    
            prev = getattr(self, "_random_enabled", False)
            self._random_enabled = bool(val)
    
            # اگر وسط اسکن تغییر کرد → صف پارت‌ها rebuild شود
            if getattr(self, "scanning", False) and (self._random_enabled != prev):
                self._rebuild_remaining_after_part = True
                self._log(
                    f"🔁 Random changed during run → "
                    f"will rebuild remaining queue after current part "
                    f"(now: {'ON' if self._random_enabled else 'OFF'})"
                )
    
            # --- مدیریت Auto ---
            auto_val = False
            if hasattr(self, "chk_auto") and self.chk_auto is not None:
                try:
                    auto_val = self.chk_auto.isChecked()
                except Exception:
                    pass
    
            if hasattr(self, "btn_auto") and self.btn_auto is not None:
                try:
                    auto_val = auto_val or self.btn_auto.isChecked()
                except Exception:
                    pass
    
            self._auto_enabled = bool(auto_val)
    
        except Exception as ex:
            self._err(f"_sync_random_auto: {ex}")

#==========================================================================
#       UI KEYSPACE  (synced with ui_controls for Random/Auto)
#==========================================================================
    def _ui_keyspace(self):
        g = QGroupBox("🎯 Keyspace & Time / Parts / Loops")
        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(10)
        grid.setContentsMargins(10, 10, 10, 10)
    
        # ---- ورودی‌ها
        self.start_bit = QLineEdit("1");   self.start_bit.setFixedWidth(70)
        self.end_bit   = QLineEdit("256"); self.end_bit.setFixedWidth(70)
        self.parts_spin      = QSpinBox();  self.parts_spin.setRange(1, 10000);    self.parts_spin.setValue(100)
        self.time_per_part   = QSpinBox();  self.time_per_part.setRange(1, 120);   self.time_per_part.setValue(3)
        self.time_per_part.setSuffix(" min")
        self.start_part_spin = QSpinBox();  self.start_part_spin.setRange(1, 10000);      self.start_part_spin.setValue(1)
        self.max_loops_spin  = QSpinBox();  self.max_loops_spin.setRange(0, 1_000_000);   self.max_loops_spin.setValue(0)
        self.start_loop_spin = QSpinBox();  self.start_loop_spin.setRange(1, 1_000_000);  self.start_loop_spin.setValue(1)
    
        # ---- چک‌باکس‌ها و گزینه‌ها
        self.chk_random = QCheckBox("🔀 Random Order")
        self.chk_auto   = QCheckBox("🤖 Auto Start")
        self.chk_save   = QCheckBox("💾 Save Settings"); self.chk_save.setChecked(True)
    
        # 🎲 ComboBox حالت رندوم
        self.random_mode_box = QComboBox()
        self.random_mode_box.addItems([
            "Reproducible (loop-based)",
            "Fully Random"
        ])
        self.random_mode_box.setCurrentIndex(0)  # پیش‌فرض reproducible
        self.random_mode_box.setEnabled(False)
        self.chk_random.stateChanged.connect(
            lambda state: self.random_mode_box.setEnabled(bool(state))
        )
        self.random_mode_box.currentIndexChanged.connect(
            lambda i: setattr(self, "random_mode", "reproducible" if i == 0 else "fully")
        )
        self.random_mode = "reproducible"
    
        # ---- اتصال تغییرات
        self.chk_random.stateChanged.connect(self._sync_random_auto)
        self.chk_auto.stateChanged.connect(self._sync_random_auto)
        self.time_per_part.valueChanged.connect(self._on_time_changed)
        self.start_bit.textChanged.connect(self._update_range_hex)
        self.end_bit.textChanged.connect(self._update_range_hex)
    
        # ───────── ردیف ۱: بیت‌ها + پارت + زمان ─────────
        grid.addWidget(QLabel("Start Bit:"),        0, 0); grid.addWidget(self.start_bit,      0, 1)
        grid.addWidget(QLabel("End Bit:"),          0, 2); grid.addWidget(self.end_bit,        0, 3)
        grid.addWidget(QLabel("Parts:"),            0, 4); grid.addWidget(self.parts_spin,     0, 5)
        grid.addWidget(QLabel("Minutes/Part:"),     0, 6); grid.addWidget(self.time_per_part,  0, 7)
    
        # ───────── ردیف ۲: مدیریت پارت/لوپ ─────────
        grid.addWidget(QLabel("Start from Part #"), 1, 0); grid.addWidget(self.start_part_spin, 1, 1)
        grid.addWidget(QLabel("Max Loops (0=∞)"),   1, 2); grid.addWidget(self.max_loops_spin,  1, 3)
        grid.addWidget(QLabel("Start from Loop #"), 1, 4); grid.addWidget(self.start_loop_spin, 1, 5)
    
        # ───────── خط جداکننده ─────────
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        grid.addWidget(sep, 2, 0, 1, 8)
    
        # ───────── ردیف ۳: چک‌باکس‌ها (راست‌چین) ─────────
        hbox_opts = QHBoxLayout()
        hbox_opts.addStretch(1)
        hbox_opts.addWidget(self.chk_random)
        hbox_opts.addWidget(self.random_mode_box)
        hbox_opts.addWidget(self.chk_auto)
        hbox_opts.addWidget(self.chk_save)
        grid.addLayout(hbox_opts, 3, 0, 1, 8)
    
        g.setLayout(grid)
    
        # همگام‌سازی اولیه
        try:
            br = getattr(self, "btn_random", None)
            if br is not None:
                bs = self.chk_random.blockSignals(True)
                self.chk_random.setChecked(br.isChecked())
                self.chk_random.blockSignals(bs)
            ba = getattr(self, "btn_auto", None)
            if ba is not None:
                bs = self.chk_auto.blockSignals(True)
                self.chk_auto.setChecked(ba.isChecked())
                self.chk_auto.blockSignals(bs)
        except Exception:
            pass
        
        try:
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(0, self._sync_random_auto)
        except Exception:
            pass
        
        return g
    # ---------------------- Custom Subrange UI ----------------------
    def _ui_subrange(self):
        """UI group: choose percent-location, blocks, subparts and enable custom-only mode."""
        g = QGroupBox("🎯 Target Subrange / Percent Picker")
        layout = QGridLayout()

        # percent location (0-100)
        self.percent_spin = QSpinBox()
        self.percent_spin.setRange(0, 100)
        self.percent_spin.setValue(70)
        self.percent_spin.setSuffix(" %")

        # NEW: percent range start..end (e.g. 85..90)
        self.percent_start_spin = QSpinBox()
        self.percent_start_spin.setRange(0,100)
        self.percent_start_spin.setValue(85)
        self.percent_start_spin.setSuffix(' %')
        self.percent_end_spin = QSpinBox()
        self.percent_end_spin.setRange(0,100)
        self.percent_end_spin.setValue(90)
        self.percent_end_spin.setSuffix(' %')

        # divide into N blocks (default 10)
        self.divide_blocks_spin = QSpinBox()
        self.divide_blocks_spin.setRange(1, 256)
        self.divide_blocks_spin.setValue(10)

        # pick which block index (1..N)
        self.block_index_spin = QSpinBox()
        self.block_index_spin.setRange(1, 256)
        self.block_index_spin.setValue(10)

        # subdivide that block into M parts (pparts)
        self.subparts_spin = QSpinBox()
        self.subparts_spin.setRange(1, 10000)
        self.subparts_spin.setValue(100)

        # parts per target-subpart (how many DEMO parts each subpart will be split to)
        self.parts_per_subpart_spin = QSpinBox()
        self.parts_per_subpart_spin.setRange(1, 10000)
        self.parts_per_subpart_spin.setValue(10)

        # minutes per small part when using percent-range split
        self.percent_part_minutes_spin = QSpinBox()
        self.percent_part_minutes_spin.setRange(1,120)
        self.percent_part_minutes_spin.setValue(3)
        self.percent_part_minutes_spin.setSuffix(' min')

        # enable toggle
        self.chk_custom_subrange = QCheckBox("Enable Target-Only Subrange")

        # buttons
        btn_preview = QPushButton("Preview Subparts")
        btn_apply = QPushButton("Apply as Parts")

        btn_preview.clicked.connect(self._preview_subrange)
        btn_apply.clicked.connect(self._apply_subrange_as_parts)

        # layout
        layout.addWidget(QLabel("Percent location:"), 0, 0); layout.addWidget(self.percent_spin, 0, 1)
        layout.addWidget(QLabel("Divide into blocks:"), 0, 2); layout.addWidget(self.divide_blocks_spin, 0, 3)
        layout.addWidget(QLabel("Pick block #:"), 1, 0); layout.addWidget(self.block_index_spin, 1, 1)
        layout.addWidget(QLabel("Subdivide block into parts:"), 1, 2); layout.addWidget(self.subparts_spin, 1, 3)
        layout.addWidget(QLabel("Parts per subpart:"), 2, 0); layout.addWidget(self.parts_per_subpart_spin, 2, 1)
        layout.addWidget(self.chk_custom_subrange, 2, 2, 1, 2)

        h = QHBoxLayout(); h.addWidget(btn_preview); h.addWidget(btn_apply);
        # NEW percent-range preview/apply
        btn_preview_percent = QPushButton('Preview Percent-Range Parts')
        btn_apply_percent = QPushButton('Apply Percent-Range as Parts')
        h.addWidget(btn_preview_percent); h.addWidget(btn_apply_percent);
        h.addStretch(1)
        layout.addLayout(h, 3, 0, 1, 4)

        g.setLayout(layout)
        return g

    # ---------------------- Target Manager UI ----------------------
    def _ui_target_manager(self):
        """UI for creating / editing multiple targets and saving/loading profiles."""
        g = QGroupBox("🎯 Target Manager (bit ranges / single bits / percent positions)")
        lay = QGridLayout()

        # Controls to add a new target
        self.t_type_box = QComboBox()
        self.t_type_box.addItems(["bit_range", "single_bit", "percent_pos", "hex_range"])
        self.t_type_box.setToolTip("نوع هدف: بازه بیت، تک‌بیت، موقعیت درصدی، یا بازه hex")

        self.t_start_bit = QLineEdit("131"); self.t_start_bit.setFixedWidth(80)
        self.t_end_bit   = QLineEdit("160"); self.t_end_bit.setFixedWidth(80)
        self.t_percent   = QSpinBox(); self.t_percent.setRange(0,100); self.t_percent.setValue(70); self.t_percent.setSuffix(" %")
        self.t_width_bits = QSpinBox(); self.t_width_bits.setRange(1,256); self.t_width_bits.setValue(14); self.t_width_bits.setSuffix(" bits")
        self.t_parts_per_target = QSpinBox(); self.t_parts_per_target.setRange(1,10000); self.t_parts_per_target.setValue(10)
        self.t_minutes_per_part = QSpinBox(); self.t_minutes_per_part.setRange(1,120); self.t_minutes_per_part.setValue(1)

        btn_add = QPushButton("➕ Add Target")
        btn_del = QPushButton("🗑 Delete Selected")
        btn_preview = QPushButton("🔎 Preview Parts")
        btn_apply = QPushButton("✅ Apply Targets")

        # list widget (simple table)
        self.t_list = QTableWidget(0, 6)
        self.t_list.setHorizontalHeaderLabels(["type","a","b/percent","width","parts","min/part"])
        self.t_list.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.t_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        lay.addWidget(QLabel("Type:"), 0, 0); lay.addWidget(self.t_type_box, 0, 1)
        lay.addWidget(QLabel("Start Bit / Hex / Value:"), 0, 2); lay.addWidget(self.t_start_bit, 0, 3)
        lay.addWidget(QLabel("End Bit / - / Percent:"), 0, 4); lay.addWidget(self.t_end_bit, 0, 5)
        lay.addWidget(QLabel("Width (bits):"), 1, 0); lay.addWidget(self.t_width_bits, 1, 1)
        lay.addWidget(QLabel("Parts/Target:"), 1, 2); lay.addWidget(self.t_parts_per_target, 1, 3)
        lay.addWidget(QLabel("Minutes/part:"), 1, 4); lay.addWidget(self.t_minutes_per_part, 1, 5)

        h = QHBoxLayout(); h.addWidget(btn_add); h.addWidget(btn_del); h.addWidget(btn_preview); h.addWidget(btn_apply); h.addStretch(1)
        lay.addLayout(h, 2, 0, 1, 6)
        lay.addWidget(self.t_list, 3, 0, 1, 6)

        # profile save/load
        h2 = QHBoxLayout()
        self.profile_name = QLineEdit("")
        btn_save_profile = QPushButton("Save Profile")
        btn_load_profile = QPushButton("Load Profile")
        h2.addWidget(QLabel("Profile name:")); h2.addWidget(self.profile_name); h2.addWidget(btn_save_profile); h2.addWidget(btn_load_profile)
        lay.addLayout(h2, 4, 0, 1, 6)

        g.setLayout(lay)

        # signals
        btn_add.clicked.connect(self._add_target_from_ui)
        btn_del.clicked.connect(self._delete_selected_targets)
        btn_preview.clicked.connect(lambda: self._preview_targets(parts_limit=50))
        btn_apply.clicked.connect(lambda: self._apply_targets_as_parts())
        btn_save_profile.clicked.connect(self._save_profile_dialog)
        btn_load_profile.clicked.connect(self._load_profile_dialog)

        return g

    # ---------------------- Target list helpers ----------------------
    def _add_target_from_ui(self):
        """Read UI controls and append a target to self._targets (list of dicts)."""
        try:
            typ = self.t_type_box.currentText()
            a = self.t_start_bit.text().strip()
            b = self.t_end_bit.text().strip()
            width = int(self.t_width_bits.value())
            parts = int(self.t_parts_per_target.value())
            minutes = int(self.t_minutes_per_part.value())

            t = {"type": typ, "a": a, "b": b, "width_bits": width, "parts": parts, "minutes": minutes}
            if not hasattr(self, "_targets"):
                self._targets = []
            self._targets.append(t)
            self._refresh_targets_table()
            self._log(f"➕ Target added: {t}")
        except Exception as ex:
            self._err(f"_add_target_from_ui: {ex}")

    def _delete_selected_targets(self):
        try:
            sel = sorted(set(it.row() for it in self.t_list.selectedItems()), reverse=True)
            if not sel:
                return
            for r in sel:
                del self._targets[r]
            self._refresh_targets_table()
        except Exception as ex:
            self._err(f"_delete_selected_targets: {ex}")

    def _refresh_targets_table(self):
        try:
            if not hasattr(self, "_targets"):
                self._targets = []
            self.t_list.setRowCount(len(self._targets))
            for i, t in enumerate(self._targets):
                vals = [
                    t.get("type", ""),
                    str(t.get("a", "")),
                    str(t.get("b", "")),
                    str(t.get("width_bits", "")),
                    str(t.get("parts", "")),
                    str(t.get("minutes", ""))
                ]
                for j, v in enumerate(vals):
                    it = QTableWidgetItem(v)
                    # جلوگیری از ویرایش سلول
                    flags = it.flags()
                    flags &= ~Qt.ItemFlag.ItemIsEditable
                    it.setFlags(flags)
                    self.t_list.setItem(i, j, it)
        except Exception as ex:
            self._err(f"_refresh_targets_table: {ex}")

    # ---------------------- Convert single target -> parts ranges ----------------------
    def _target_to_parts(self, target):
        """
        Convert a target dict to a list of (start_hex, end_hex) tuples.
        Supported target types:
          - bit_range: a=start_bit, b=end_bit  (integers)
          - single_bit: a=bit_index (integer) -> treat as start==end
          - percent_pos: a=ignored, b=percent (0..100), width_bits (bits around that pos)
             meaning: choose subrange centered at percent of full keyspace [start_bit..end_bit_ui]
          - hex_range: a=hexstart, b=hexend (hex strings)
        NOTE: uses self.start_bit / self.end_bit UI as overall keyspace when percent_pos used.
        """
        out = []
        try:
            typ = target.get("type")
            parts = int(target.get("parts", 1))
            minutes = int(target.get("minutes", 1))

            if typ == "bit_range":
                s = int(target.get("a"))
                e = int(target.get("b"))
                # split numeric keyspace of [s..e] into `parts` equal parts:
                start_int = 1 << (s - 1)
                end_int = (1 << e) - 1
                total = Decimal(end_int) - Decimal(start_int) + 1
                size = total / Decimal(parts)
                for i in range(parts):
                    a = int(start_int + i * size)
                    b = int(start_int + (i + 1) * size - 1) if i < parts - 1 else end_int
                    out.append((f"{a:X}", f"{b:X}", minutes))
                return out

            if typ == "single_bit":
                bit = int(target.get("a"))
                s_int = 1 << (bit - 1)
                e_int = (1 << bit) - 1
                out.append((f"{s_int:X}", f"{e_int:X}", minutes))
                return out

            if typ == "hex_range":
                a_hex = str(target.get("a")).strip()
                b_hex = str(target.get("b")).strip()
                # assume hex strings; normalize
                out.append((a_hex.upper(), b_hex.upper(), minutes))
                return out

            if typ == "percent_pos":
                # percent is in target['b']
                percent = float(target.get("b") or 0.0)
                width_bits = int(target.get("width_bits") or 1)
                # overall keyspace from UI
                s_ui = int(self.start_bit.text())
                e_ui = int(self.end_bit.text())
                # compute numeric keyspace and center
                start_int = 1 << (s_ui - 1)
                end_int = (1 << e_ui) - 1
                total = Decimal(end_int) - Decimal(start_int) + 1
                # center position (0..1)
                pos = clamp(percent/100.0, 0.0, 1.0)
                # map pos to integer coordinate
                center = int(start_int + Decimal(pos) * (total - 1))
                # now width in numeric = 2^width_bits (approx)
                width_count = (1 << width_bits)
                half = width_count // 2
                a = max(start_int, center - half)
                b = min(end_int, center + half)
                # split this small subrange into `parts`
                sub_total = Decimal(b) - Decimal(a) + 1
                psize = max(1, int(sub_total / Decimal(parts)))
                cur = a
                for i in range(parts):
                    if i < parts - 1:
                        nxt = min(b, cur + psize - 1)
                    else:
                        nxt = b
                    out.append((f"{cur:X}", f"{nxt:X}", minutes))
                    cur = nxt + 1
                    if cur > b:
                        break
                return out

            # fallback
            return out
        except Exception as ex:
            self._err(f"_target_to_parts: {ex}")
            return out

    # ---------------------- Build parts from all targets ----------------------
    def _build_parts_from_targets(self):
        """Builds self._custom_parts_list from self._targets (each element yields tuples with minutes)."""
        try:
            if not hasattr(self, "_targets") or not self._targets:
                self._log("⚠️ No targets defined.")
                return []
            all_parts = []
            for t in self._targets:
                lst = self._target_to_parts(t)
                # lst elements are (start_hex, end_hex, minutes)
                for (a, b, minutes) in lst:
                    all_parts.append({"start": a, "end": b, "minutes": int(minutes)})
            # save as expected format: list of tuples
            self._custom_parts_list = [(p["start"], p["end"]) for p in all_parts]
            # optionally store minutes mapping
            self._custom_parts_minutes = [p["minutes"] for p in all_parts]
            self._log(f"🔧 Built {len(self._custom_parts_list)} parts from {len(self._targets)} targets.")
            return self._custom_parts_list
        except Exception as ex:
            self._err(f"_build_parts_from_targets: {ex}")
            return []

    # ---------------------- Preview combined targets (small limit) ----------------------
    def _preview_targets(self, parts_limit=50):
        try:
            parts = []
            for t in (getattr(self, "_targets", []) or []):
                parts.extend(self._target_to_parts(t))
                if len(parts) >= parts_limit:
                    break
            if not parts:
                self._log("⚠️ No parts to preview.")
                return
            self._log(f"🔍 Preview {min(len(parts), parts_limit)} parts (type,start..end,minutes):")
            for i, (a, b, mins) in enumerate(parts[:parts_limit], start=1):
                self._log(f"  {i:03d}: {a} .. {b} ({mins} min)")
        except Exception as ex:
            self._err(f"_preview_targets: {ex}")

    # ---------------------- Apply targets as parts (set parts_spin and custom list) ----------------------
    def _apply_targets_as_parts(self):
        try:
            lst = self._build_parts_from_targets()
            if not lst:
                self._err("No parts generated from targets.")
                return
            try:
                self.parts_spin.setValue(len(lst))
            except Exception:
                pass
            self._log(f"✅ Applied targets -> {len(lst)} parts. Use Start Scan to run.")
        except Exception as ex:
            self._err(f"_apply_targets_as_parts: {ex}")

    # ---------------------- Profiles (DB-backed) ----------------------
    def _save_profile_dialog(self):
        try:
            name = (self.profile_name.text() or "").strip()
            if not name:
                self._err("Profile name required.")
                return
            data = {"targets": getattr(self, "_targets", []), "created": datetime.now().isoformat()}
            j = json.dumps(data)
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            # ensure table
            c.execute("CREATE TABLE IF NOT EXISTS profiles (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, data TEXT, created_at TEXT)")
            c.execute("INSERT OR REPLACE INTO profiles (name, data, created_at) VALUES (?, ?, ?)", (name, j, datetime.now().isoformat()))
            conn.commit(); conn.close()
            self._log(f"💾 Profile '{name}' saved.")
        except Exception as ex:
            self._err(f"_save_profile_dialog: {ex}")

    def _load_profile_dialog(self):
        try:
            # show simple selection by loading all profile names to a small dialog (or just load by exact name)
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            try:
                c.execute("SELECT name, data FROM profiles ORDER BY name COLLATE NOCASE")
                rows = c.fetchall()
            except Exception:
                rows = []
            conn.close()
            if not rows:
                self._err("No profiles in DB.")
                return
            # simple modal: if profile_name filled, load that, else load first
            name = (self.profile_name.text() or "").strip()
            if name:
                row = next((r for r in rows if r[0] == name), None)
                if not row:
                    self._err("Profile not found.")
                    return
            else:
                row = rows[0]
            data = json.loads(row[1])
            self._targets = data.get("targets", [])
            self._refresh_targets_table()
            self._log(f"📂 Profile '{row[0]}' loaded ({len(self._targets)} targets).")
        except Exception as ex:
            self._err(f"_load_profile_dialog: {ex}")

    # ---------------------- Helper: compute percent subrange ----------------------
    def _compute_percent_subrange(self, start_bit: int, end_bit: int, percent: float, blocks: int, block_index: int):
        s = int(start_bit); e = int(end_bit)
        if s > e:
            s, e = e, s
        start_int = 1 << (s - 1)
        end_int = (1 << e) - 1
        total = Decimal(end_int) - Decimal(start_int) + 1
        size = total / Decimal(blocks)

        # use percent if percent in [0..100], otherwise use provided block_index
        try:
            p = float(percent)
            if 0 <= p <= 100:
                # map percent to a 0-based block index
                bi = int(clamp(round((p/100.0) * blocks) - 1, 0, blocks - 1))
            else:
                bi = clamp(int(block_index) - 1, 0, blocks - 1)
        except Exception:
            bi = clamp(int(block_index) - 1, 0, blocks - 1)

        a = int(start_int + bi * size)
        if bi < blocks - 1:
            b = int(start_int + (bi + 1) * size - 1)
        else:
            b = end_int
        return a, b

    # ---------------------- Build custom parts list ----------------------
    def _build_custom_parts_for_percent(self):
        try:
            s = int(self.start_bit.text())
            e = int(self.end_bit.text())
        except Exception:
            self._err("Invalid start/end bits for custom subrange")
            return []

        percent = int(self.percent_spin.value())
        blocks = int(self.divide_blocks_spin.value())
        block_idx = int(self.block_index_spin.value())
        subparts = int(self.subparts_spin.value())
        parts_per_sub = int(self.parts_per_subpart_spin.value())

        block_start_int, block_end_int = self._compute_percent_subrange(s, e, percent, blocks, block_idx)

        total = Decimal(block_end_int) - Decimal(block_start_int) + 1
        sub_size = total / Decimal(subparts)

        out = []
        for i in range(subparts):
            a = int(block_start_int + i * sub_size)
            if i < subparts - 1:
                b = int(block_start_int + (i + 1) * sub_size - 1)
            else:
                b = block_end_int
            sub_total = Decimal(b) - Decimal(a) + 1
            psize = max(1, int(sub_total / Decimal(parts_per_sub)))
            if psize <= 0:
                out.append((f"{a:X}", f"{b:X}"))
            else:
                cur = a
                for p in range(parts_per_sub):
                    if p < parts_per_sub - 1:
                        nxt = min(b, cur + psize - 1)
                    else:
                        nxt = b
                    if nxt < cur:
                        nxt = cur
                    out.append((f"{cur:X}", f"{nxt:X}"))
                    cur = nxt + 1
                    if cur > b:
                        break
        self._custom_parts_list = out
        return out


    # ---------------------- Percent-Range builder & handlers ----------------------
    def _build_parts_from_percent_range(self, start_percent:int, end_percent:int, subparts:int, parts_per_sub:int, minutes_per_part:int):
        # Build parts list from a percent-range [start_percent..end_percent] of the overall keyspace.
        out = []
        try:
            s_ui = int(self.start_bit.text())
            e_ui = int(self.end_bit.text())
        except Exception:
            self._err("Invalid start/end bits for percent-range")
            return out

        start_pct = clamp(int(start_percent), 0, 100)
        end_pct = clamp(int(end_percent), 0, 100)
        if end_pct < start_pct:
            start_pct, end_pct = end_pct, start_pct

        # compute absolute numeric range for UI keyspace
        start_int = 1 << (s_ui - 1)
        end_int = (1 << e_ui) - 1
        total = Decimal(end_int) - Decimal(start_int) + 1

        # map percent to coordinates (inclusive)
        a = int(start_int + Decimal(start_pct/100.0) * (total - 1))
        b = int(start_int + Decimal(end_pct/100.0) * (total - 1))
        if a < start_int: a = start_int
        if b > end_int: b = end_int
        if b < a:
            b = a

        # Now split [a..b] into subparts, then each subpart into parts_per_sub parts
        if subparts <= 0:
            subparts = 1
        sub_total = Decimal(b) - Decimal(a) + 1
        sub_size = max(1, int(sub_total / Decimal(subparts)))
        cur = a
        for si in range(subparts):
            if si < subparts - 1:
                sub_end = min(b, cur + sub_size - 1)
            else:
                sub_end = b
            # split this subrange into parts_per_sub
            p_total = Decimal(sub_end) - Decimal(cur) + 1
            psize = max(1, int(p_total / Decimal(parts_per_sub)))
            pcur = cur
            for pi in range(parts_per_sub):
                if pi < parts_per_sub - 1:
                    pnxt = min(sub_end, pcur + psize - 1)
                else:
                    pnxt = sub_end
                out.append((f"{pcur:X}", f"{pnxt:X}", int(minutes_per_part)))
                pcur = pnxt + 1
                if pcur > sub_end:
                    break
            cur = sub_end + 1
            if cur > b:
                break
        # store minutes mapping too
        try:
            self._custom_parts_minutes = [t[2] for t in out]
            self._custom_parts_list = [(t[0], t[1]) for t in out]
        except Exception:
            pass
        return out

    def _preview_percent_range_parts(self):
        try:
            start_pct = int(getattr(self, 'percent_start_spin').value())
            end_pct = int(getattr(self, 'percent_end_spin').value())
            subparts = int(getattr(self, 'subparts_spin').value())
            parts_per_sub = int(getattr(self, 'parts_per_subpart_spin').value())
            mins = int(getattr(self, 'percent_part_minutes_spin').value())
            parts = self._build_parts_from_percent_range(start_pct, end_pct, subparts, parts_per_sub, mins)
            if not parts:
                self._log('⚠️ Percent-range produced no parts')
                return
            self._log(f"🔍 Percent-range produced {len(parts)} parts. First 20:")
            for i, (a,b,m) in enumerate(parts[:20], start=1):
                self._log(f"  {i:03d}: {a} .. {b} ({m} min)")
        except Exception as ex:
            self._err(f"_preview_percent_range_parts: {ex}")

    def _apply_percent_range_as_parts(self):
        try:
            start_pct = int(getattr(self, 'percent_start_spin').value())
            end_pct = int(getattr(self, 'percent_end_spin').value())
            subparts = int(getattr(self, 'subparts_spin').value())
            parts_per_sub = int(getattr(self, 'parts_per_subpart_spin').value())
            mins = int(getattr(self, 'percent_part_minutes_spin').value())
            parts = self._build_parts_from_percent_range(start_pct, end_pct, subparts, parts_per_sub, mins)
            if not parts:
                self._err('No parts generated from percent-range.')
                return
            # update parts_spin and internal lists
            try:
                self.parts_spin.setValue(len(parts))
            except Exception:
                pass
            # store minutes list
            try:
                self._custom_parts_minutes = [p[2] for p in parts]
                self._custom_parts_list = [(p[0], p[1]) for p in parts]
            except Exception:
                pass
            # persist custom parts to DB (as JSON) for resume
            try:
                import sqlite3, json as _json
                conn = sqlite3.connect(self.db_path); c = conn.cursor()
                c.execute("INSERT OR IGNORE INTO progress (id) VALUES (1)")
                j = _json.dumps([{"start":a,"end":b,"minutes":m} for (a,b,m) in parts])
                try:
                    c.execute("UPDATE progress SET custom_parts_json = ? WHERE id = 1", (j,))
                except Exception:
                    try:
                        c.execute("ALTER TABLE progress ADD COLUMN custom_parts_json TEXT")
                        c.execute("UPDATE progress SET custom_parts_json = ? WHERE id = 1", (j,))
                    except Exception:
                        pass
                conn.commit(); conn.close()
            except Exception:
                pass
            self._log(f"✅ Applied percent-range -> {len(parts)} parts. Use Start Scan to run.")
        except Exception as ex:
            self._err(f"_apply_percent_range_as_parts: {ex}")
    # ---------------------- Preview and Apply ----------------------
    def _preview_subrange(self):
        try:
            lst = self._build_custom_parts_for_percent()
            if not lst:
                self._log("⚠️ Custom subrange produced no parts")
                return
            self._log(f"🔍 Custom subrange produced {len(lst)} parts. First 10:")
            for i, (a, b) in enumerate(lst[:10], start=1):
                self._log(f"  {i:03d}: {a} .. {b}")
        except Exception as ex:
            self._err(f"_preview_subrange: {ex}")

    def _apply_subrange_as_parts(self):
        try:
            lst = self._build_custom_parts_for_percent()
            if not lst:
                self._err("No parts to apply")
                return
            self._custom_parts_list = lst
            try:
                self.parts_spin.setValue(len(lst))
            except Exception:
                pass
            self._log(f"✅ Applied custom subrange: {len(lst)} parts (will be used on next split).")
        except Exception as ex:
            self._err(f"_apply_subrange_as_parts: {ex}")

    # ---------------------- Integration: override _split_keyspace if custom list present ----------------------
    def _split_keyspace(self):
        try:
            if hasattr(self, '_custom_parts_list') and self._custom_parts_list:
                return [(a, b) for (a, b) in self._custom_parts_list]
        except Exception:
            pass
        if hasattr(self, '_split_keyspace_orig'):
            return self._split_keyspace_orig()
        return []


#==========================================================================
#   UI RANGE HEX
#==========================================================================
    def _ui_range_hex(self):
        g = QGroupBox("⭕ Range HEX Display")
        h = QGridLayout()
        self.start_hex = QLineEdit(); self.start_hex.setReadOnly(True)
        self.end_hex   = QLineEdit(); self.end_hex.setReadOnly(True)
        h.addWidget(QLabel("Start HEX:"), 0,0); h.addWidget(self.start_hex, 0,1)
        h.addWidget(QLabel("End HEX:"),   1,0); h.addWidget(self.end_hex,   1,1)
        g.setLayout(h); return g

#==========================================================================
#   UI GPU
#==========================================================================
    def _ui_gpu(self):
        g = QGroupBox("🟢 GPU Settings")
        h = QHBoxLayout()

        # --- انتخاب GPU
        self.gpu_box = QComboBox()
        self.gpu_box.setMinimumWidth(260)
        h.addWidget(QLabel("GPU:"))
        h.addWidget(self.gpu_box)

        # --- پارامترهای پردازش
        self.block = QComboBox();  
        self.block.addItems(["8","16","32","64","128","256"]);  
        self.block.setCurrentText("32")

        self.thread = QComboBox();  
        self.thread.addItems(["64","128","256","512"]);  
        self.thread.setCurrentText("128")

        self.points = QComboBox();  
        self.points.addItems(["32","64","128","256","512","1024"]);  
        self.points.setCurrentText("128")

        self.stride = QLineEdit("1"); self.stride.setFixedWidth(70)

        for lbl, w in [("Block", self.block), ("Thread", self.thread), ("Points", self.points), ("Stride", self.stride)]:
            h.addWidget(QLabel(lbl + ":"))
            h.addWidget(w)

        # --- درصد استفاده GPU
        self.gpu_util = QSpinBox()
        self.gpu_util.setRange(10, 100)       # حداقل 10%، حداکثر 100%
        self.gpu_util.setValue(80)           # پیش‌فرض: 80%
        self.gpu_util.setSuffix(" %")
        h.addWidget(QLabel("GPU Util:"))
        h.addWidget(self.gpu_util)

        # --- ذخیره پایدار GPU
        self.chk_persist_gpu = QCheckBox("Save GPU settings")
        self.chk_persist_gpu.setChecked(True)
        h.addWidget(self.chk_persist_gpu)

        h.addStretch(1)
        QTimer.singleShot(0, self._detect_gpus_to_ui)

        g.setLayout(h)
        return g
#==========================================================================
#   UI INPUT FILE
#==========================================================================
    def _ui_input_file(self):
        g = QGroupBox("🟠 Input Targets")
        h = QHBoxLayout()
        self.input_file = QLineEdit(INPUT_FILE_DEFAULT)
        btn = QPushButton("Browse"); btn.clicked.connect(self._browse_file)
        h.addWidget(QLabel("Targets .txt:")); h.addWidget(self.input_file); h.addWidget(btn)

        # ✅ Address mode (compressed / uncompressed)
        self.look_mode = QComboBox()
        self.look_mode.addItems(["compressed","uncompressed"])
        self.look_mode.setToolTip("انتخاب نوع آدرس برای بررسی: آدرس‌های فشرده (compressed) یا غیرفشرده (uncompressed)")
        h.addWidget(QLabel("Address:")); h.addWidget(self.look_mode)

        g.setLayout(h)
        return g
#==========================================================================
#       UI LIVE STATUS
#==========================================================================
    def _ui_live_status(self):
        from PyQt6.QtWidgets import QGroupBox, QGridLayout, QWidget, QHBoxLayout, QLabel,     QFrame
    
        g = QGroupBox("📡 Live Key | PARTS | GPU | CPU | RAM | Status  ")
        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(8)
        grid.setContentsMargins(10, 10, 10, 10)
    
        # ── Row 0: GPU + SYS strip (single line)
        if not hasattr(self, "lbl_gpu_line"):
            self.lbl_gpu_line = QLabel("🟢 GPU: —")
        if not hasattr(self, "lbl_sys"):
            self.lbl_sys = QLabel("🖥 CPU/RAM/GPU: —")
    
        self.lbl_gpu_line.setToolTip("نام/مدل GPU و VRAM (از nvidia-smi یا خروجی BitCrack)")
        self.lbl_sys.setToolTip("وضعیت لحظه‌ای سیستم (CPU/RAM/GPU Util)")
    
        strip = QWidget()
        h = QHBoxLayout(strip)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(12)
    
        vline = QFrame()
        vline.setFrameShape(QFrame.Shape.VLine)
        vline.setFrameShadow(QFrame.Shadow.Sunken)
        vline.setStyleSheet("color:#d0d0d0;")
    
        h.addWidget(self.lbl_gpu_line)
        h.addWidget(vline)
        h.addWidget(self.lbl_sys)
        h.addStretch(1)
    
        grid.addWidget(strip, 0, 0, 1, 3)
    
        # ── Row 1: horizontal separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        sep.setStyleSheet("color:#d0d0d0; margin: 2px 0;")
        grid.addWidget(sep, 1, 0, 1, 3)
    
        # ── Row 2: status / time
        self.lbl_status     = QLabel("🔴 STATUS: STOPPED")
        self.lbl_time_part  = QLabel("⏱ TIME (PART): 00:00")
        self.lbl_time_total = QLabel("🕰 TOTAL TIME: 00:00:00")
        self.lbl_status.setToolTip("وضعیت اسکن: RUNNING / STOPPED / ERROR")
        self.lbl_time_part.setToolTip("زمان سپری‌شده برای پارت جاری")
        self.lbl_time_total.setToolTip("زمان کل سشن")
        grid.addWidget(self.lbl_status,     2, 0)
        grid.addWidget(self.lbl_time_part,  2, 1)
        grid.addWidget(self.lbl_time_total, 2, 2)
    
        # ── Row 3: part / loops / speed
        self.lbl_part_no    = QLabel("🔢 PART#: 0 / 0")
        self.lbl_part_rnd   = QLabel("🔀 RANDOM PART#: 0 / 0")  # ← اضافه شد
        self.lbl_loops      = QLabel("🔁 LOOPS: 0 / ∞")
        self.lbl_part_no.setToolTip("شماره پارت جاری / کل پارت‌ها")
        self.lbl_part_rnd.setToolTip("شماره پارت فعلی در حالت رندوم / کل پارت‌ها")
        self.lbl_loops.setToolTip("شمارندهٔ لوپ‌ها (از 1 به بالا)")
        grid.addWidget(self.lbl_part_no,  3, 0)
        grid.addWidget(self.lbl_part_rnd, 3, 1)
        grid.addWidget(self.lbl_loops,    3, 2)
    
        # ── Row 4: counters
        self.lbl_part_keys  = QLabel("🗝 PART KEY: 0")
        self.lbl_total_keys = QLabel("🔐 TOTAL FOUND: 0")
        self.lbl_found      = QLabel("🔎 FOUND COUNT: 0")
        self.lbl_part_keys.setToolTip("تعداد کلیدهای تولیدی در پارت جاری")
        self.lbl_total_keys.setToolTip("مجموع کلیدهای پیدا شده (Found) در کل سشن")
        self.lbl_found.setToolTip("شمارش Found طبق دیتابیس (progress.found_count)")
        grid.addWidget(self.lbl_part_keys,  4, 0)
        grid.addWidget(self.lbl_total_keys, 4, 1)
        grid.addWidget(self.lbl_found,      4, 2)
    
        # ── Row 5: targets / tested-total
        self.lbl_targets = QLabel("🎯 TARGETS: —")
        self.lbl_tested  = QLabel("🧮 TESTED TOTAL: 0")
        self.lbl_speed   = QLabel("⚡ SPEED: 0 MKey/s")
        self.lbl_targets.setToolTip("تعداد آدرس‌های هدف (targets) از خروجی BitCrack")
        self.lbl_tested.setToolTip("کل کلیدهای تست‌شده طبق خروجی BitCrack (total)")
        self.lbl_speed.setToolTip("سرعت لحظه‌ای BitCrack")
        grid.addWidget(self.lbl_targets, 5, 0)
        grid.addWidget(self.lbl_tested,  5, 1, 1, 2)
        grid.addWidget(self.lbl_speed,   5, 2)

    
        g.setLayout(grid)
        return g

#==========================================================================
#     REFRESH TOTAL PART RND
#===========================================================================
    def _refresh_total_part_rnd(self):
        """
        نمایش تعداد پارت‌های اجرا شده در حالت Random
        """
        try:
            total_parts = int(self.parts_spin.value()) if hasattr(self, "parts_spin") else 0
            done = getattr(self, "_random_parts_done", 0)
    
            if hasattr(self, "lbl_part_rnd"):
                if getattr(self, "_random_enabled", False):
                    self.lbl_part_rnd.setText(f"🔀 RANDOM PART#: {done}/{total_parts}")
                else:
                    self.lbl_part_rnd.setText("🔀 RANDOM PART#: —")
        except Exception as ex:
            if hasattr(self, "_err"):
                self._err(f"_refresh_total_part_rnd: {ex}")
    
#==========================================================================
#       UI PROGRESS
#==========================================================================
    def _ui_progress(self):
        g = QGroupBox("📢 Progress Monitor")
        v = QVBoxLayout()

        # نوار کنترل‌ها (خیلی خلوت)
        h = QHBoxLayout()
        self.chk_tail_last = QCheckBox("Last line only")
        self.chk_autoscroll = QCheckBox("Auto-scroll"); self.chk_autoscroll.setChecked(True)
        btn_clear = QPushButton("Clear")
        btn_open_found = QPushButton("📂 Open Found Folder")
        btn_export_csv = QPushButton("⬇️ Export Found CSV")
        btn_open_db    = QPushButton("🗄 Open DB")     
        btn_view_db    = QPushButton("👁 View Found (DB)")
     

        btn_open_found.clicked.connect(self.open_found_folder)
        btn_export_csv.clicked.connect(lambda: self.export_found_to_csv())
        btn_open_db.clicked.connect(lambda: self.open_db_file())
        btn_view_db.clicked.connect(lambda: self.open_found_viewer())


        h.addWidget(btn_open_found)
        h.addWidget(btn_export_csv)
        h.addWidget(btn_open_db)
        h.addWidget(btn_view_db)
                        

        h.addWidget(self.chk_tail_last)
        h.addWidget(self.chk_autoscroll)
        h.addStretch(1)
        h.addWidget(btn_clear)
        v.addLayout(h)

        # ویجت «آخرین خط»
        self.last_line_lbl = QLabel("—")
        self.last_line_lbl.setStyleSheet("font-family: Consolas, 'Courier New', monospace;")
        self.last_line_lbl.setVisible(False)  # پیش‌فرض: خاموش
        v.addWidget(self.last_line_lbl)

        # جعبه‌ی لاگ کامل
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMinimumHeight(120)
        try:
            # محدودیت تعداد خطوط برای جلوگیری از مصرف زیاد RAM
            self.log_box.document().setMaximumBlockCount(5000)
        except Exception:
            pass
        v.addWidget(self.log_box)

        # اتصال سیگنال‌ها
        self.chk_tail_last.toggled.connect(self._toggle_tail_last)
        self.last_line_lbl.setVisible(self.chk_tail_last.isChecked())
        self.log_box.setVisible(not self.chk_tail_last.isChecked())
        btn_clear.clicked.connect(self._clear_logs)

        g.setLayout(v)
        return g
#==========================================================================
#       TOGGLE TAIL LAST
#==========================================================================
    def _toggle_tail_last(self, checked: bool):
        """سوئیچ بین 'آخرین خط' و 'نمایش کامل' + ذخیره در settings"""
        try:
            # فقط UI
            self.last_line_lbl.setVisible(checked)
            self.log_box.setVisible(not checked)

            # ذخیره در DB
            try:
                self._ensure_settings_schema()
                conn = sqlite3.connect(self.db_path); c = conn.cursor()

                # آیا ردیف settings(id=1) داریم؟
                c.execute("SELECT 1 FROM settings WHERE id=1")
                row = c.fetchone()

                if not row:
                    # seed با مقادیر فعلی UI (نوع‌ها درست ست می‌شوند)
                    start_bit = int(self.start_bit.text() or 0)
                    end_bit   = int(self.end_bit.text() or 0)
                    parts     = int(self.parts_spin.value() or 0)
                    minutes   = int(self.time_per_part.value() or 1)

                    rand  = int(self.chk_random.isChecked() or (hasattr(self, "btn_random") and self.btn_random.isChecked()))
                    auto  = int(self.chk_auto.isChecked()   or (hasattr(self, "btn_auto")   and self.btn_auto.isChecked()))

                    block  = int(self.block.currentText())
                    thread = int(self.thread.currentText())
                    points = int(self.points.currentText())
                    stride = int(self.stride.text() or "1")

                    inpf = (self.input_file.text() or "").strip()
                    look = (self.look_mode.currentText() or "compressed").strip().lower()
                    if look not in ("compressed", "uncompressed"):
                        look = "compressed"

                    persist   = int(self.chk_persist_gpu.isChecked())
                    tail_last = 1 if checked else 0

                    c.execute("""
                        INSERT INTO settings
                            (id, start_bit, end_bit, parts, minutes, random_order, auto_start,
                             block, thread, points, stride, input_file, look, persist_gpu, tail_last)
                        VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (start_bit, end_bit, parts, minutes, rand, auto,
                          block, thread, points, stride, inpf, look, persist, tail_last))
                else:
                    c.execute("UPDATE settings SET tail_last=? WHERE id=1", (1 if checked else 0,))

                conn.commit(); conn.close()
            except Exception as ex:
                self._err(f"tail_last save: {ex}")

        except Exception as ex:
            self._err(f"_toggle_tail_last: {ex}")

#========================================================================================
#       APPLY TAIL LAST FROM DB
#========================================================================================
    def _apply_tail_last_from_db(self):
        """وضعیت ذخیره‌شدهٔ tail_last را به UI اعمال می‌کند (پس از آماده بودن DB)."""
        try:
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            c.execute("SELECT tail_last FROM settings WHERE id=1")
            row = c.fetchone(); conn.close()
            checked = bool(row and int(row[0]) == 1)
        except Exception:
            checked = False
        # فقط UI؛ ذخیره لازم نیست (خود مقدار از DB آمده)
        self.chk_tail_last.setChecked(checked)
        self.last_line_lbl.setVisible(checked)
        self.log_box.setVisible(not checked)

#==========================================================================
#   APPEND LOG LINE
#==========================================================================
    def _append_log_line(self, text: str, typ: str = "INFO"):
        """افزودن لاگ به UI (و DB) با رعایت حالت Last-line و Auto-scroll"""
        try:
            s = str(text).rstrip()
            # نمایش UI
            if hasattr(self, "chk_tail_last") and self.chk_tail_last.isChecked():
                # فقط آخرین خط
                self.last_line_lbl.setText(s)
            else:
                # نمایش کامل
                if hasattr(self, "log_box") and self.log_box:
                    self.log_box.append(s)
                    if getattr(self, "chk_autoscroll", None) and self.chk_autoscroll.isChecked():
                        try:
                            from PyQt6.QtGui import QTextCursor
                        except Exception:
                            try:
                                from PyQt5.QtGui import QTextCursor
                            except Exception:
                                QTextCursor = None
                        if QTextCursor is not None:
                            self.log_box.moveCursor(QTextCursor.MoveOperation.End)
            # ذخیره در DB
            try:
                if self.db_path:
                    conn = sqlite3.connect(self.db_path); c = conn.cursor()
                    c.execute("INSERT INTO logs(typ, message, ts) VALUES(?,?,?)",
                              (typ, s, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                    conn.commit(); conn.close()

                if not self.db_path or not os.path.exists(self.db_path):
                    return  # هنوز DB آماده نیست؛ فقط UI را آپدیت کن
            except Exception:
                pass

        except Exception as ex:
            try:
                # اگر UI در دسترس نیست، حداقل روی استدین چاپ شود
                print("LOG UI error:", ex, "| line:", text)
            except Exception:
                pass

#==========================================================================
#           LOG
#==========================================================================
    def _log(self, message):
        self._append_log_line(message, "INFO")

#==========================================================================
#           ERROR
#==========================================================================
    def _err(self, message):
        # ست کردن وضعیت قرمز، اگر لیبل هست
        if hasattr(self, "lbl_status"):
            self.lbl_status.setText("🔴 STATUS: ERROR")
        self._append_log_line(f"⛔ {message}", "ERROR")
#==========================================================================
#           CLEAR LOGS
#==========================================================================
    def _clear_logs(self):
        try:
            if self.db_path:
                conn = sqlite3.connect(self.db_path); c = conn.cursor()
                c.execute("DELETE FROM logs")
                conn.commit(); conn.close()
        except Exception:
            pass
#=============================================================================
#        UI CONTROLS
#===============================================================================
    def _ui_controls(self):
        v = QVBoxLayout()
        h1 = QHBoxLayout()
    
        # 1) ساخت دکمه‌ها
        self.btn_apply  = QPushButton("✔️ Apply Settings")
        self.btn_start  = QPushButton("▶️ Start Scan")
        self.btn_toggle = QPushButton("⏸ Pause")        # دکمهٔ دوحالته Pause/Resume
        self.btn_hard   = QPushButton("🛑 Hard Stop")
        self.btn_reset  = QPushButton("♻️ Reset")
        self.btn_save   = QPushButton("💾 Save")
        self.btn_load   = QPushButton("📥 Load")
    
        # ✅ سازگاری عقب‌رو
        self.btn_stop = self.btn_toggle
    
        # 2) اتصال سیگنال‌ها
        self.btn_apply.clicked.connect(self.apply_settings)
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_toggle.clicked.connect(self.on_click_pause_resume)
        self.btn_hard.clicked.connect(self.stop_scan_hard)
        self.btn_reset.clicked.connect(self.reset_scan)
        self.btn_save.clicked.connect(self._save_settings)
        self.btn_load.clicked.connect(self._load_settings)
    
        # 3) افزودن به لایوت
        for w in [self.btn_apply, self.btn_start, self.btn_toggle, self.btn_hard,
                  self.btn_reset, self.btn_save, self.btn_load]:
            h1.addWidget(w)
    
        v.addLayout(h1)
        return v

# ======================================================================================
# ------------------------- Settings / DB -------------------------
#====================================================================================
    def apply_settings(self):
        if not self._apply_settings_folder(create=True): return
        self._init_db()
        if self.chk_save.isChecked(): self._save_settings()
        self._update_range_hex()
        self._log(f"✅ Settings applied to: {self.session_folder}")
        self._sync_random_auto()
        if self._is_auto_enabled() and not self.scanning:
            QTimer.singleShot(200, self.start_scan)  # کمی تأخیر برای به‌روز شدن UI

#==========================================================================
#   APPLY SETTING FOLDER
#==========================================================================
    def _apply_settings_folder(self, create=True):
       try:
           s = int(self.start_bit.text())
           e = int(self.end_bit.text())
           p = self.parts_spin.value()
           m = self.time_per_part.value()   
           # اجازه می‌ده start == end هم معتبر باشه
           if not (1 <= s <= e <= 256):
               self._err("Invalid bit range.")
               return False 
           if not (1 <= p <= 10000):
               self._err("Parts out of range.")
               return False 
           if not (1 <= m <= 120):
               self._err("Minutes/part out of range.")
               return False 
           name = f"SCAN_{s}to{e}_{p}parts_{m}min"
           self.session_folder = os.path.join(self.base_dir, name)
           self._save_last_session_path()   
           if create:
               os.makedirs(self.session_folder, exist_ok=True)  
           self.db_path = os.path.join(self.session_folder, "progress.db")
           self.part_minutes = m
           self.max_loops = self.max_loops_spin.value()
           return True  
       except Exception as ex:
           self._err(f"_apply_settings_folder: {ex}")
           return False
 
#==========================================================================
#   INIT DB
#==========================================================================
    def _init_db(self):
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        except Exception:
            pass
        
        # --- PRAGMAs (خارج از تراکنش)
        try:
            with sqlite3.connect(self.db_path, isolation_level=None) as con:
                con.execute("PRAGMA journal_mode=WAL;")
                con.execute("PRAGMA synchronous=NORMAL;")
                con.execute("PRAGMA temp_store=MEMORY;")
                con.execute("PRAGMA foreign_keys=ON;")
        except Exception:
            pass
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
    
        # --- جدول‌ها
        c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY,
            start_bit INTEGER,
            end_bit INTEGER,
            parts INTEGER,
            minutes INTEGER,
            random_order INTEGER,
            auto_start INTEGER,
            block INTEGER,
            thread INTEGER,
            points INTEGER,
            stride INTEGER,
            input_file TEXT,
            look TEXT,
            persist_gpu INTEGER,
            tail_last INTEGER DEFAULT 0
        )
        """)
    
        c.execute("""
        CREATE TABLE IF NOT EXISTS progress (
            id INTEGER PRIMARY KEY,
            last_part INTEGER DEFAULT 0,
            elapsed_seconds REAL DEFAULT 0,
            total_keys INTEGER DEFAULT 0,
            loop_count INTEGER DEFAULT 0,
            max_loops INTEGER DEFAULT 0,
            found_count INTEGER DEFAULT 0,
            processed_total REAL DEFAULT 0
        )
        """)
    
        c.execute("""
        CREATE TABLE IF NOT EXISTS parts (
            part_index INTEGER PRIMARY KEY,
            start_hex TEXT,
            end_hex TEXT,
            done INTEGER DEFAULT 0,
            elapsed_in_part REAL DEFAULT 0,
            part_keys INTEGER DEFAULT 0,
            processed_in_part REAL DEFAULT 0,
            start_time TEXT,
            end_time TEXT,
            reason TEXT
        )
        """)
    
        c.execute("""
        CREATE TABLE IF NOT EXISTS found_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            part_index INTEGER,
            address TEXT,
            privkey TEXT,
            timestamp TEXT
        )
        """)
    
        c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            typ TEXT,
            message TEXT,
            ts TEXT
        )
        """)
    
        # --- افزودن ستون‌های جاافتاده
        def ensure_cols(table, wanted: dict):
            c.execute(f"PRAGMA table_info({table})")
            cols = {row[1] for row in c.fetchall()}
            for col, ddl in wanted.items():
                if col not in cols:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
    
        ensure_cols('settings', {
            'minutes':     "minutes INTEGER DEFAULT 1",
            'stride':      "stride INTEGER DEFAULT 1",
            'look':        "look TEXT DEFAULT 'compressed'",
            'persist_gpu': "persist_gpu INTEGER DEFAULT 0",
            'tail_last':   "tail_last INTEGER DEFAULT 0",
        })
    
        ensure_cols('progress', {
            'found_count':     "found_count INTEGER DEFAULT 0",
            'processed_total': "processed_total REAL DEFAULT 0",
            'tested_total':    "tested_total INTEGER DEFAULT 0",
            'updated_at':      "updated_at TEXT"
        })
    
        ensure_cols('parts', {
            'processed_in_part': "processed_in_part REAL DEFAULT 0",
            'reason':            "reason TEXT"
        })
    
        ensure_cols('found_keys', {
            'privkey':   "privkey TEXT",
            'timestamp': "timestamp TEXT"
        })
    
        # --- ردیف اولیه progress
        c.execute("""
        INSERT OR IGNORE INTO progress
        (id,last_part,elapsed_seconds,total_keys,loop_count,max_loops,found_count,processed_total)
        VALUES(1,0,0,0,0,0,0,0)
        """)
    
        # --- پاکسازی Duplicateها در found_keys
        try:
            c.execute("""
            DELETE FROM found_keys
            WHERE rowid NOT IN (
                SELECT MIN(rowid)
                FROM found_keys
                GROUP BY address, COALESCE(privkey,'')
            )
            """)
        except Exception:
            pass
        
        # --- ایندکس‌ها
        try:
            c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_found_addr_pk ON found_keys(address, privkey)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_found_ts   ON found_keys(timestamp)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_found_part ON found_keys(part_index)")
        except Exception:
            pass
        
        conn.commit()
        conn.close()
    
        try:
            self._ensure_progress_schema()
        except Exception:
            pass

# ======================================================================
#   ENSURE SETTING SCHEMA
#==========================================================================
    def _ensure_settings_schema(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                # جدول اصلی
                c.execute("""
                    CREATE TABLE IF NOT EXISTS settings (
                        id INTEGER PRIMARY KEY,
                        start_bit INTEGER,
                        end_bit INTEGER,
                        parts INTEGER,
                        minutes INTEGER,
                        random_order INTEGER,
                        random_mode TEXT,
                        auto_start INTEGER,
                        block INTEGER,
                        thread INTEGER,
                        points INTEGER,
                        stride INTEGER,
                        input_file TEXT,
                        look TEXT,
                        persist_gpu INTEGER,
                        tail_last INTEGER,
                        gpu_util INTEGER,
                        start_loop INTEGER
                    )
                """)
    
                # ستون‌های جدید را اگر وجود ندارند اضافه کن
                def add_column(name, coltype, default=None):
                    try:
                        if default is not None:
                            c.execute(f"ALTER TABLE settings ADD COLUMN {name} {coltype} DEFAULT {default}")
                        else:
                            c.execute(f"ALTER TABLE settings ADD COLUMN {name} {coltype}")
                    except sqlite3.OperationalError:
                        pass  # ستون وجود دارد
                    
                add_column("random_mode", "TEXT", "'reproducible'")
                add_column("gpu_util", "INTEGER", 100)
                add_column("start_loop", "INTEGER", 1)
    
                conn.commit()
        except Exception as ex:
            self._err(f"_ensure_settings_schema: {ex}")

# ==========================================================================
#       SAVE SETTINGS AND LOAD SETTINGS
#==========================================================================                                                                             
    def _safe_int(self, val, default=0):
        """تبدیل امن مقدار به int (با مقدار پیش‌فرض در صورت None یا خطا)."""
        try:
            if val is None:
                return default
            if isinstance(val, (int, float)):
                return int(val)
            s = str(val).strip()
            return int(s) if s else default
        except Exception:
            return default

    def _save_settings(self):
        try:
            self._ensure_settings_schema()

            start_bit = self._safe_int(getattr(self.start_bit, "text", lambda: "1")(), 1)
            end_bit   = self._safe_int(getattr(self.end_bit, "text", lambda: "256")(), 256)
            parts     = self._safe_int(getattr(self.parts_spin, "value", lambda: 100)(), 100)
            minutes   = self._safe_int(getattr(self.time_per_part, "value", lambda: 3)(), 3)
            minutes   = max(1, min(30, minutes))

            rand  = int(getattr(self, "_random_enabled", False))
            auto  = int(getattr(self, "_auto_enabled", False))
            rand_mode = getattr(self, "random_mode", "reproducible")

            block  = self._safe_int(getattr(self.block, "currentText", lambda: "32")(), 32)
            thread = self._safe_int(getattr(self.thread, "currentText", lambda: "128")(), 128)
            points = self._safe_int(getattr(self.points, "currentText", lambda: "128")(), 128)

            stride_val = None
            if hasattr(self, "stride"):
                if hasattr(self.stride, "text"):
                    stride_val = self.stride.text()
                elif hasattr(self.stride, "value"):
                    stride_val = self.stride.value()
            stride = self._safe_int(stride_val, 1)

            gpu_util = self._safe_int(getattr(self.gpu_util, "value", lambda: 100)(), 100)

            inpf = (self.input_file.text() if hasattr(self, "input_file") else "").strip()
            lk   = self.look_mode.currentText().strip().lower() if hasattr(self, "look_mode") else "compressed"
            look = "compressed" if lk not in ("compressed", "uncompressed") else lk

            persist   = int(getattr(self, "chk_persist_gpu", None) and self.chk_persist_gpu.isChecked())
            tail_last = int(getattr(self, "chk_tail_last", None) and self.chk_tail_last.isChecked())
            start_loop = self._safe_int(getattr(self.start_loop_spin, "value", lambda: 1)(), 1)

            vals = (start_bit, end_bit, parts, minutes, rand, rand_mode, auto,
                    block, thread, points, stride, inpf, look, persist,
                    tail_last, gpu_util, start_loop)

            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT INTO settings
                        (id, start_bit, end_bit, parts, minutes, random_order, random_mode, auto_start,
                         block, thread, points, stride, input_file, look, persist_gpu,
                         tail_last, gpu_util, start_loop)
                    VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        start_bit=excluded.start_bit,
                        end_bit=excluded.end_bit,
                        parts=excluded.parts,
                        minutes=excluded.minutes,
                        random_order=excluded.random_order,
                        random_mode=excluded.random_mode,
                        auto_start=excluded.auto_start,
                        block=excluded.block,
                        thread=excluded.thread,
                        points=excluded.points,
                        stride=excluded.stride,
                        input_file=excluded.input_file,
                        look=excluded.look,
                        persist_gpu=excluded.persist_gpu,
                        tail_last=excluded.tail_last,
                        gpu_util=excluded.gpu_util,
                        start_loop=excluded.start_loop
                """, vals)

            self._log("✅ Settings saved.")
        except Exception as ex:
            self._err(f"_save_settings: {ex}")
    def _load_settings(self):
        if not self.db_path or not os.path.exists(self.db_path):
            return
        try:
            self._ensure_settings_schema()
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            c.execute("""
                SELECT
                    start_bit, end_bit, parts, minutes, random_order, random_mode, auto_start,
                    block, thread, points, stride, input_file, look, persist_gpu,
                    tail_last, gpu_util, start_loop
                FROM settings WHERE id=1
            """)
            row = c.fetchone(); conn.close()
            if not row:
                return

            (s, e, p, m, rand, rand_mode, auto, blk, th, pts, strd,
             inpf, lk, persist, tail_last, gpu_util, start_loop) = row

            # keyspace
            self.start_bit.setText(str(self._safe_int(s, 1)))
            self.end_bit.setText(str(self._safe_int(e, 256)))
            self.parts_spin.setValue(self._safe_int(p, 100))
            self.time_per_part.setValue(max(1, min(30, self._safe_int(m, 3))))

            def _set_combo_safe(combo, value, default):
                try:
                    if combo is None: return
                    idx = combo.findText(str(value))
                    if idx < 0:
                        idx = combo.findText(str(default))
                    if idx >= 0:
                        combo.setCurrentIndex(idx)
                except Exception:
                    pass

            _set_combo_safe(self.block,  blk, 32)
            _set_combo_safe(self.thread, th, 128)
            _set_combo_safe(self.points, pts, 128)

            if hasattr(self.stride, "setText"):
                self.stride.setText(str(self._safe_int(strd, 1)))

            if hasattr(self.gpu_util, "setValue"):
                self.gpu_util.setValue(self._safe_int(gpu_util, 100))

            if hasattr(self, "input_file"):
                self.input_file.setText(inpf or "")

            if hasattr(self, "look_mode"):
                lk = (lk or "compressed").lower()
                if lk not in ("compressed", "uncompressed"):
                    lk = "compressed"
                self.look_mode.setCurrentText(lk)

            if hasattr(self, "chk_persist_gpu"):
                self.chk_persist_gpu.setChecked(bool(persist))

            for w, val in ((getattr(self, "btn_random", None), bool(rand)),
                           (getattr(self, "chk_random", None), bool(rand)),
                           (getattr(self, "btn_auto",   None), bool(auto)),
                           (getattr(self, "chk_auto",   None), bool(auto))):
                if w is not None:
                    bs = w.blockSignals(True)
                    w.setChecked(val)
                    w.blockSignals(bs)

            # random_mode
            if hasattr(self, "random_mode_box"):
                if rand_mode == "fully":
                    self.random_mode_box.setCurrentIndex(1)
                    self.random_mode = "fully"
                else:
                    self.random_mode_box.setCurrentIndex(0)
                    self.random_mode = "reproducible"

            if hasattr(self, "_sync_random_auto"):
                self._sync_random_auto()

            if hasattr(self, "chk_tail_last"):
                bs = self.chk_tail_last.blockSignals(True)
                self.chk_tail_last.setChecked(bool(tail_last))
                self.chk_tail_last.blockSignals(bs)
                if hasattr(self, "last_line_lbl") and hasattr(self, "log_box"):
                    show_last = self.chk_tail_last.isChecked()
                    self.last_line_lbl.setVisible(show_last)
                    self.log_box.setVisible(not show_last)

            if hasattr(self, "start_loop_spin"):
                self.start_loop_spin.setValue(self._safe_int(start_loop, 1))

            if hasattr(self, "_update_range_hex"):
                self._update_range_hex()

            self._log("✅ Settings loaded.")
        except Exception as ex:
            self._err(f"_load_settings: {ex}")

#==========================================================================
#       ON TIME CHANGED
#==========================================================================
    def _on_time_changed(self, v):
        self.part_minutes = clamp(int(v), 1, 120)
        self._log(f"⏱ Minutes/part set to {self.part_minutes} (applies to remaining parts)")
#==========================================================================
#           BROWSE FILE
#==========================================================================
    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose .txt file", self.base_dir, "Text Files (*.txt)")
        if path: self.input_file.setText(path)
#==========================================================================
#       CLI FLAG AUTO DETECT
#==========================================================================
    def _detect_cli(self):
        """Detect BitCrack CLI flags robustly with graceful fallbacks."""
        if self._cli_flags:
            return self._cli_flags

        exe = self._resolve_bitcrack()
        default = {
            'in': '--in', 'device': '--device',
            'compressed': '--compressed', 'uncompressed': '--uncompressed',
            'blocks': '--blocks', 'threads': '--threads', 'points': '--points', 'stride': '--stride',
            'keyspace': '--keyspace'
        }
        if not exe:
            self._cli_flags = default
            return self._cli_flags

        try:
            out = subprocess.check_output(
                [exe, '--help'],
                text=True, stderr=subprocess.STDOUT,
                cwd=self.base_dir, timeout=5
            )
        except Exception:
            self._cli_flags = default
            return self._cli_flags

        def present(*alts: str) -> bool:
            return any(a in out for a in alts)

        flags = {}

        # --in / -i / --input
        flags['in'] = '--in' if present('--in ', '\n  --in', ' --in') \
            else ('-i' if present(' -i ', '\n  -i', ' -i,') \
            else ('--input' if present('--input ') else '--in'))

        # --device / -d / --gpu
        flags['device'] = '--device' if present('--device', '\n  --device') \
            else ('-d' if present(' -d ', '\n  -d') \
            else ('--gpu' if present('--gpu') else '--device'))

        # --compressed / -c / --compress
        flags['compressed'] = '--compressed' if present('--compressed', '\n  --compressed') \
            else ('-c' if present(' -c ', '\n  -c') \
            else ('--compress' if present('--compress') else '--compressed'))

        # --uncompressed / -u / --uncompress
        flags['uncompressed'] = '--uncompressed' if present('--uncompressed', '\n  --uncompressed') \
            else ('-u' if present(' -u ', '\n  -u') \
            else ('--uncompress' if present('--uncompress') else '--uncompressed'))

        # blocks / threads / points / stride
        flags['blocks']  = '--blocks'  if present('--blocks', '\n  --blocks', ' -b ') else ('-b' if present(' -b ', '\n  -b') else '--blocks')
        flags['threads'] = '--threads' if present('--threads','\n  --threads',' -t ') else ('-t' if present(' -t ', '\n  -t') else '--threads')
        flags['points']  = '--points'  if present('--points', '\n  --points', ' -p ') else ('-p' if present(' -p ', '\n  -p') else '--points')

        # بعضی نسخه‌ها stride را با -k دارند
        flags['stride']  = '--stride' if present('--stride', '\n  --stride') else ('-k' if present(' -k ', '\n  -k') else '--stride')

        # keyspace
        flags['keyspace'] = '--keyspace' if present('--keyspace') else ('-s' if present(' -s ', '\n  -s') else '--keyspace')

        self._cli_flags = flags
        self._log(f"🧭 Detected CLI flags: {self._cli_flags}")
        return flags
#==========================================================================
#           KEY SPACE SPLIT
#==========================================================================
    def _split_keyspace_orig(self):
        s = int(self.start_bit.text())
        e = int(self.end_bit.text())
        parts = self.parts_spin.value()

        start_int = 1 << (s - 1)
        end_int   = (1 << e) - 1
        total = Decimal(end_int) - Decimal(start_int) + 1

        # اگر رنج خیلی کوچک‌تر از تعداد پارت‌هاست، پارت‌ها رو محدود کن
        if total < parts:
            parts = int(total)  # یا حداقل 1
        if parts < 1:
            parts = 1

        size = total / Decimal(parts)
        out = []

        for i in range(parts):
            a = int(start_int + i * size)
            if i < parts - 1:
                b = int(start_int + (i + 1) * size - 1)
            else:
                b = end_int

            # جلوگیری از خطای a > b
            if b < a:
                b = a

            out.append((f"{a:X}", f"{b:X}"))

        return out

#==========================================================================
#           ENSURE PARTS TABLE
#==========================================================================
    def _ensure_parts_table(self):
        """
        ساخت/همسان‌سازی جدول parts با رنج فعلی، حفظ وضعیت قبلی و آماده‌سازی برای  رزوم واقعی.
        - اگر رنج و تعداد پارت‌ها تغییری نکرده باشد: هیچ ریستی انجام نمی‌شود.
        - اگر تغییر داشته باشد: فقط پارت‌های تغییر کرده ساخته/به‌روز می‌شوند، وضعیت    همتاهای دقیق حفظ می‌گردد.
        """
        ranges = self._split_keyspace()  # [(start_hex, end_hex), ...]
        total_parts = len(ranges)

        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()

            # خواندن وضعیت فعلی parts
            cur_rows = c.execute("""
                SELECT part_index, start_hex, end_hex, done,
                       elapsed_in_part, part_keys,
                       COALESCE(processed_in_part,0), start_time,
                       end_time, reason
                FROM parts
                ORDER BY part_index
            """).fetchall()

            # اگر خالی بود: یکجا بساز
            if not cur_rows:
                for idx, (a, b) in enumerate(ranges, start=1):
                    c.execute("""
                        INSERT INTO parts(part_index,start_hex,end_hex,
                            done,elapsed_in_part,part_keys,
                            processed_in_part,reason)
                        VALUES(?,?,?,?,?,?,?,?)
                    """, (idx, a, b, 0, 0.0, 0, 0.0,
                          "new" if total_parts == self.parts_spin.value() else  "clamped"))
                conn.commit(); conn.close()
                self.current_part = self._compute_resume_part()
                if hasattr(self, "lbl_part_no"):
                    self.lbl_part_no.setText(f"🔢 PART#: {int(self.current_part)}/  {total_parts}")
                return

            # اگر تعداد پارت‌ها برابر و همه‌ی (start_hex,end_hex) ها برابر است →  هیچ تغییری لازم نیست
            cur_ranges = [(r[1], r[2]) for r in cur_rows]
            if len(cur_ranges) == total_parts and all((a1 == a2 and b1 == b2) for   (a1,b1),(a2,b2) in zip(cur_ranges, ranges)):
                # فقط لیبل را به‌روز کن و current_part را بر اساس رزوم واقعی ست کن
                self.current_part = self._compute_resume_part()
                if hasattr(self, "lbl_part_no"):
                    self.lbl_part_no.setText(f"🔢 PART#: {int(self.current_part)}/  {total_parts}")
                conn.close()
                return

            # تغییر داریم: نقشه‌ی قدیمی بر اساس (start,end) برای حفظ وضعیت
            old_by_range = {(r[1], r[2]): r for r in cur_rows}

            # جدول را بازنویسی «کنترل‌شده» انجام می‌دهیم:
            c.execute("DELETE FROM parts")
            for idx, (a, b) in enumerate(ranges, start=1):
                if (a, b) in old_by_range:
                    _pi, _sa, _sb, done, elp, pkeys, pinp, st, en, rsn =    old_by_range[(a, b)]
                    c.execute("""
                        INSERT INTO parts(part_index,start_hex,end_hex,
                            done,elapsed_in_part,part_keys,
                            processed_in_part,start_time,end_time,reason)
                        VALUES(?,?,?,?,?,?,?,?,?,?)
                    """, (idx, a, b, int(done or 0), float(elp or 0.0),
                          int(pkeys or 0), float(pinp or 0.0), st, en, rsn))
                else:
                    # رنج جدید → رکورد تازه
                    c.execute("""
                        INSERT INTO parts(part_index,start_hex,end_hex,
                            done,elapsed_in_part,part_keys,
                            processed_in_part,reason)
                        VALUES(?,?,?,?,?,?,?,?)
                    """, (idx, a, b, 0, 0.0, 0, 0.0,
                          "new-range" if total_parts == self.parts_spin.value()     else "clamped"))
            conn.commit(); conn.close()

            self.current_part = self._compute_resume_part()
            if hasattr(self, "lbl_part_no"):
                self.lbl_part_no.setText(f"🔢 PART#: {int(self.current_part)}/  {total_parts}")

        except Exception as ex:
            self._err(f"_ensure_parts_table: {ex}")
            # حداقل لیبل را به‌روز کنیم
            try:
                if hasattr(self, "lbl_part_no"):
                    self.lbl_part_no.setText(f"🔢 PART#: {int(getattr(self,     'current_part', 0))}/{len(ranges)}")
            except Exception:
                pass

#============================================================================================
    def _ensure_progress_columns(self):
        import sqlite3
        conn = sqlite3.connect(self.db_path); c = conn.cursor()
        cols = {r[1] for r in c.execute("PRAGMA table_info(progress)").fetchall()}

        if "resume_same_part" not in cols:
            c.execute("ALTER TABLE progress ADD COLUMN resume_same_part INTEGER DEFAULT 0")
        if "current_pos_hex" not in cols:
            c.execute("ALTER TABLE progress ADD COLUMN current_pos_hex TEXT")
        if "random_parts_done" not in cols:
            c.execute("ALTER TABLE progress ADD COLUMN random_parts_done INTEGER DEFAULT 0")

        conn.commit(); conn.close()

#===================================================================================
#==================================================================================
    def _undone_parts(self):
        """برگرداندن فهرست پارت‌های ناتمام (done=0) به‌ترتیب part_index."""
        try:
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            rows = c.execute("SELECT part_index FROM parts WHERE done=0 ORDER BY part_index").fetchall()
            conn.close()
            return [r[0] for r in rows]
        except Exception as ex:
            self._err(f"_undone_parts: {ex}")
            return []
#==========================================================================================
    def _is_random_enabled(self) -> bool:
        """وضعیت Random را از state داخلی یا چک‌باکس‌ها می‌خواند."""
        try:
            if hasattr(self, "_random_enabled"):
                return bool(self._random_enabled)
            cr = getattr(self, "chk_random", None)
            br = getattr(self, "btn_random", None)
            return bool((cr and cr.isChecked()) or (br and br.isChecked()))
        except Exception:
            return False

    def _get_last_part_anchor(self) -> int:
        """آخرین پارت ثبت‌شده در progress.last_part (fallback=0)."""
        last = 0
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            c.execute("SELECT last_part FROM progress WHERE id=1")
            row = c.fetchone(); conn.close()
            if row and row[0] is not None:
                last = int(row[0])
        except Exception as ex:
            self._err(f"_get_last_part_anchor: {ex}")
        return last
#========================================================================================================
    def _make_part_order_from_list(self, undone: list[int]) -> list[int]:
        """
        می‌سازد ترتیب اجرای پارت‌ها از لیست undone:
        1) ورودی را یونیک/عددی و مرتب می‌کند (برای پایداری).
        2) اگر Random روشن باشد:
           - حالت reproducible → با seed = loop_count شافل پایدار.
           - حالت fully_random → هر بار شافل متفاوت.
        3) حالت Resume-Same-Part:
           اگر در جدول progress فلگ resume_same_part=1 باشد و last_part داخل undone باشد،
           همان پارت را در ابتدای صف می‌گذارد و باقی صف طبق سیاست چرخش/رندوم ساخته می‌شود.
        4) در غیر این حالت، نسبت به last_part «چرخش» انجام می‌دهد:
           ابتدا پارت‌های > last، بعد پارت‌های <= last (strictly after).
        """

        # --- نرمال‌سازی ورودی
        try:
            xs = sorted({int(p) for p in (undone or [])})
        except Exception:
            xs = []
        if not xs:
            return []

        # --- خواندن anchor/flag از DB
        last, resume_flag = 0, 0
        try:
            import sqlite3
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                row = c.execute("SELECT last_part, resume_same_part FROM progress WHERE id=1").fetchone()
                if row:
                    last        = int(row[0] or 0)
                    resume_flag = int(row[1] or 0)
        except Exception as ex:
            self._err(f"_make_part_order_from_list/read progress: {ex}")

        # --- رندوم (دو حالت)
        try:
            if self._is_random_enabled():
                mode = getattr(self, "random_mode", "reproducible")  # پیش‌فرض
                if mode == "reproducible":
                    seed = int(getattr(self, "loop_count", 0) or 0)
                    rnd = random.Random(seed)
                    rnd.shuffle(xs)
                elif mode == "fully":
                    random.shuffle(xs)  # هر بار متفاوت
        except Exception as ex:
            self._err(f"_make_part_order_from_list/random: {ex}")

        # --- اگر قرار است "همان پارت" از Hard Stop ادامه شود → آن را جلو بینداز
        if resume_flag == 1 and last in xs:
            xs.remove(last)
            tail = [p for p in xs if p > last]
            head = [p for p in xs if p <= last]
            rest = (tail + head) if tail else xs
            return [last] + rest

        # --- اگر last=0 یا داخل xs نیست، همان ترتیب فعلی را بده
        if not last or last not in xs:
            return xs

        # --- چرخش معمولی: ابتدا > last سپس <= last
        tail = [p for p in xs if p > last]
        head = [p for p in xs if p <= last]
        return (tail + head) if tail else xs

#==============================================================================================
    def _next_part_from_queue(self):
        while self._part_queue_idx < len(self._current_part_queue):
            cand = self._current_part_queue[self._part_queue_idx]
            self._part_queue_idx += 1
            # اگر به هر دلیل همین الان done شده بود، ازش عبور کن
            if cand in self._undone_parts():
                return cand
        return None

#=====================================================================================
#===============================COMPUTE RESUME PART ======================================================
    def _compute_resume_part(self):
        """
        انتخاب نقطه‌ی شروع رزوم:
        - اگر progress.last_part داریم: از اولین ناتمامِ >= last_part شروع می‌کنیم؛ اگر نبود، از کوچک‌ترین ناتمام.
        - اگر هیچ ناتمامی نیست: 1 را برمی‌گردانیم (حالت لوپ بعدی تصمیم می‌گیرد چه کند).
        """
        # last_part از progress
        try:
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            row = c.execute("SELECT last_part FROM progress WHERE id=1").fetchone()
            conn.close()
            last_part = int(row[0] or 0) if row else 0
        except Exception:
            last_part = int(getattr(self, "current_part", 0) or 0)

        undone = self._undone_parts()
        if not undone:
            return max(1, last_part or 1)

        # نزدیک‌ترین ≥ last_part
        if last_part and any(p >= last_part for p in undone):
            for p in undone:
                if p >= last_part:
                    return p
        # وگرنه از کوچک‌ترین ناتمام
        return undone[0]
#========================================================================================
#=====================GET LAST PART FROM DB =============================================================
    def _get_last_part_from_db(self) -> int:
        try:
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            row = c.execute("SELECT last_part FROM progress WHERE id=1").fetchone()
            conn.close()
            return int(row[0] or 0) if row else int(getattr(self, "current_part", 0) or 0)
        except Exception:
            return int(getattr(self, "current_part", 0) or 0)
#========================================================================================
#===================== MAKE PART ORDER =============================================================
    def _make_part_order(self, total_parts: int):
        """
        ترتیب اجرای پارت‌ها:
        - اگر Random فعال باشد: shuffle پایدار به ازای هر loop_count
        - شروع از نزدیک‌ترین پارتِ >= last_part (رزوم واقعی)
        - احترام به StartFrom (start_part_spin)
        """
        start_from = clamp(self.start_part_spin.value(), 1, total_parts)
        order = list(range(start_from, total_parts + 1))

        # Random پایدار بر اساس شماره لوپ (تا در هر لوپ ترتیب ثابت بماند)
        if self._is_random_enabled():
            rnd = random.Random(int(getattr(self, "loop_count", 0) or 0))
            rnd.shuffle(order)

        # Rotate براساس last_part از DB
        last = self._get_last_part_from_db()
        if last in order:
            i = order.index(last)
            order = order[i:] + order[:i]

        return order

#==========================================================================
#       ENSURE FOUND KEYS SCHEMA
#==========================================================================
    def _ensure_found_keys_schema(self):
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        # ایجاد جدول اگر نبود
        c.execute("""
            CREATE TABLE IF NOT EXISTS found_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                part_index INTEGER,
                address TEXT,
                privkey TEXT
            )
        """)
        # اگر هیچ ستون زمان نداریم، اضافه کن
        cols = [r[1].lower() for r in c.execute("PRAGMA table_info(found_keys)")]
        if "timestamp" not in cols and "ts" not in cols:
            c.execute("ALTER TABLE found_keys ADD COLUMN timestamp TEXT")
        conn.commit()
        conn.close()

# ==========================================================================
#           START SCAN | PAUSE | RESUME | HARD STOP (FINAL PRO VERSION)
# ==========================================================================
    def start_scan(self):
        """Start = Resume if paused; otherwise start fresh safely (no thread overlap), with immediate DB backup."""
        # اگر در حال Pause هستیم → Resume
        if getattr(self, "scanning", False) and (
            getattr(self, "paused", False) or (hasattr(self, "pause_event") and self.pause_event.is_set())
        ):
            try:
                self.resume_scan()
            except Exception as ex:
                self._err(f"resume_scan failed: {ex}")
            return

        # جلوگیری از دوبار کلیک همزمان
        if getattr(self, "_starting", False):
            return
        self._starting = True

        try:
            # اگر اسکن از قبل در حال اجراست
            if getattr(self, "scanning", False):
                try:
                    QMessageBox.information(self, "Info", "⚠️ اسکن در حال اجراست.")
                except Exception:
                    pass
                return

            # نخ قبلی اگر زنده است، صبر کن تا تمام شود
            th = getattr(self, "scan_thread", None)
            if th and th.is_alive():
                try:
                    th.join(timeout=0.5)
                except Exception:
                    pass

            # ساخت پوشه‌ی Session و دیتابیس
            if not self._apply_settings_folder(create=True):
                return
            self._init_db()

            # =========================================================
            # 🧭 آماده‌سازی Subrange یا Targets قبل از ساخت جدول parts
            # =========================================================
            try:
                if hasattr(self, "_custom_parts_list") and self._custom_parts_list:
                    self._use_custom_parts = True
                    self._use_target_parts = False
                    self._log("🎯 Using explicit custom subrange for scan.")
                elif hasattr(self, "_targets") and self._targets:
                    self._apply_targets_as_parts()
                    self._use_custom_parts = True
                    self._use_target_parts = True
                    self._log("🔁 Auto-applied targets before start_scan()")
                else:
                    self._use_custom_parts = False
                    self._use_target_parts = False
                    self._log("🌀 Using default keyspace split (no custom range/targets).")
            except Exception as ex:
                self._err(f"start_scan: target/subrange prepare failed: {ex}")

            # نمایش نمونه‌ی ۵ پارت اول برای بررسی
            try:
                if hasattr(self, "_custom_parts_list") and self._custom_parts_list:
                    total_parts = len(self._custom_parts_list)
                    self._log(f"🧩 Total parts built: {total_parts}")
                    for i, (a, b) in enumerate(self._custom_parts_list[:min(5, total_parts)], start=1):
                        self._log(f"  {i:03d}: {a} .. {b}")
            except Exception:
                pass

            # =========================================================
            # 🔧 ادامه راه‌اندازی دیتابیس و Progress
            # =========================================================
            self._ensure_parts_table()
            self._ensure_progress_schema()
            if hasattr(self, "_ensure_resume_columns"):
                try:
                    self._ensure_resume_columns()
                except Exception as ex:
                    self._err(f"_ensure_resume_columns: {ex}")

            # تضمین وجود رکورد Progress و خواندن اطلاعات رزوم
            db_last = 0
            resume_flag = 0
            resume_pos_hex = None
            try:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                c.execute("INSERT OR IGNORE INTO progress (id, last_part) VALUES (1, 0)")
                row = c.execute(
                    "SELECT last_part, resume_same_part, current_pos_hex FROM progress WHERE id=1"
                ).fetchone()
                conn.commit()
                conn.close()
                if row:
                    db_last = int(row[0] or 0)
                    resume_flag = int(row[1] or 0)
                    resume_pos_hex = row[2] or None
            except Exception as ex:
                self._err(f"ensure progress row / read progress: {ex}")

            # تلاش برای بارگذاری progress از DB (اختیاری)
            try:
                if hasattr(self, "load_progress_db"):
                    self.load_progress_db()
            except Exception as ex:
                self._err(f"load_progress_db: {ex}")

            # =========================================================
            # ⚙️ تنظیم Anchor و Resume پارت فعلی
            # =========================================================
            try:
                if int(getattr(self, "current_part", 0) or 0) <= 0:
                    undone = []
                    try:
                        undone = self._undone_parts() or []
                    except Exception:
                        pass
                    if resume_flag == 1 and db_last > 0:
                        self.current_part = db_last
                    else:
                        self.current_part = db_last or (undone[0] if undone else 1)

                self._resume_pos_hex = resume_pos_hex if resume_pos_hex else None

                # تعیین total_parts برای نمایش در UI
                try:
                    if hasattr(self, "_custom_parts_list") and self._custom_parts_list:
                        total_parts = len(self._custom_parts_list)
                    else:
                        total_parts = len(self._split_keyspace())
                except Exception:
                    total_parts = 0

                self._log(
                    f"🔁 Resume anchor → PART {int(self.current_part)} "
                    f"(db_last={db_last}, resume_flag={resume_flag})"
                )
                try:
                    if hasattr(self, "lbl_part_no"):
                        self.lbl_part_no.setText(
                            f"🔢 PART#: {int(self.current_part)}/{int(total_parts)}"
                        )
                except Exception:
                    pass
            except Exception as ex:
                self._err(f"resume-anchor set: {ex}")

            # =========================================================
            # 💾 ذخیره تنظیمات در صورت فعال بودن گزینه Save
            # =========================================================
            try:
                if getattr(self, "chk_save", None) and self.chk_save.isChecked():
                    self._save_settings()
            except Exception as ex:
                self._err(f"_save_settings: {ex}")

            # ریست پرچم‌ها
            if hasattr(self, "stop_event"):
                self.stop_event.clear()
            if hasattr(self, "pause_event"):
                self.pause_event.clear()
            self.paused = False

            # =========================================================
            # 🔁 مقداردهی start_loop از DB یا UI
            # =========================================================
            start_loop_val = 1
            try:
                with sqlite3.connect(self.db_path) as conn:
                    c = conn.cursor()
                    row = c.execute("SELECT start_loop FROM progress WHERE id=1").fetchone()
                    if row and row[0]:
                        start_loop_val = int(row[0])
            except Exception:
                pass

            # اولویت با مقدار UI
            try:
                if hasattr(self, "start_loop_spin"):
                    ui_val = int(self.start_loop_spin.value() or 1)
                    if ui_val > 1:
                        start_loop_val = ui_val
            except Exception:
                pass

            self.start_loop = start_loop_val
            self.loop_count = 0
            self.current_loop = self.start_loop
            self._log(f"🚀 Scan starting from Loop #{self.start_loop}")

            # =========================================================
            # ⏱ آماده‌سازی تایمر و وضعیت UI
            # =========================================================
            self.scanning = True
            self.start_range_time = time.time()
            try:
                self.part_minutes = int(self.time_per_part.value())
            except Exception:
                self.part_minutes = int(getattr(self, "part_minutes", 3) or 3)

            try:
                if hasattr(self, "lbl_status"):
                    self.lbl_status.setText("🟢 STATUS: RUNNING")
                if hasattr(self, "btn_start"):
                    self.btn_start.setText("▶️ Start Scan")
                if hasattr(self, "btn_toggle"):
                    self.btn_toggle.setText("⏸ Pause")
                if hasattr(self, "btn_stop"):
                    self.btn_stop.setText("⏸ Pause")
            except Exception:
                pass

            # =========================================================
            # 💽 بکاپ فوری دیتابیس
            # =========================================================
            try:
                if hasattr(self, "_backup_db"):
                    self._backup_db(min_interval=0.0)
            except Exception as ex:
                self._err(f"_backup_db@start: {ex}")

            # =========================================================
            # 🚦 اجرای نخ اسکن اصلی
            # =========================================================
            t = threading.Thread(target=self._scan_loop, daemon=True)
            self.scan_thread = t
            t.start()

            if not t.is_alive():
                self.scanning = False
                self.paused = False
                try:
                    if hasattr(self, "lbl_status"):
                        self.lbl_status.setText("🔴 STATUS: STOPPED")
                except Exception:
                    pass

        except Exception as ex:
            self.scanning = False
            self.paused = False
            try:
                if hasattr(self, "lbl_status"):
                    self.lbl_status.setText("🔴 STATUS: STOPPED")
            except Exception:
                pass
            self._err(f"start_scan failed: {ex}")

        finally:
            self._starting = False

  
    # ========================================================================================
    # --------------------------------------  STOP SCAN (Soft Pause) -------------------------
    def stop_scan(self):
        """Stop = Pause نرم."""
        if not getattr(self, "scanning", False):
            return
        if hasattr(self, "pause_event"): self.pause_event.set()
        self.paused = True
        try:
            if hasattr(self, "lbl_status"): self.lbl_status.setText("⏸ STATUS: PAUSED")
            if hasattr(self, "btn_start"):  self.btn_start.setText("▶️ Resume")
            if hasattr(self, "btn_toggle"): self.btn_toggle.setText("▶️ Resume")
            if hasattr(self, "btn_stop"):   self.btn_stop.setText("▶️ Resume")  # سازگاری
        except Exception:
            pass
        try:
            if hasattr(self, "_backup_db"):
                self._backup_db(min_interval=0.0)
        except Exception:
            pass
        # اگر می‌خواهی Stop واقعاً سخت باشد، به‌جای این تابع از stop_scan_hard استفاده کن.
    
    # ========================================================================================
    # --------------------------------------  PAUSE SCAN  -----------------------------------
    def pause_scan(self):
        """Pause current scan immediately (set pause_event, suspend process, update UI)."""
        try:
            if not getattr(self, "scanning", False):
                self._log("ℹ️ Scan is not running.")
                return
            if getattr(self, "paused", False) or (hasattr(self, "pause_event") and self.pause_event.is_set()):
                self._log("⏸ Already paused.")
                return
    
            if hasattr(self, "pause_event"):
                self.pause_event.set()
            self.paused = True
    
            # تعلیق پروسس فعلی برای توقف آنی
            try:
                proc = getattr(self, "process", None)
                if proc and proc.poll() is None:
                    psutil.Process(proc.pid).suspend()
            except Exception as ex:
                self._err(f"pause suspend: {ex}")
    
            # UI
            try:
                if hasattr(self, "lbl_status"): self.lbl_status.setText("⏸ STATUS: PAUSED")
                if hasattr(self, "btn_toggle"): self.btn_toggle.setText("▶️ Resume")
                if hasattr(self, "btn_stop"):   self.btn_stop.setText("▶️ Resume")  # سازگاری
            except Exception:
                pass
            
            # بکاپ سریع
            try:
                if hasattr(self, "_backup_db"): self._backup_db(min_interval=0.0)
            except Exception:
                pass
            
            self._log("⏸ Paused.")
        except Exception as ex:
            self._err(f"pause_scan: {ex}")
    
    # ========================================================================================
    # -------------------------------------- RESUME SCAN ------------------------------------
    def resume_scan(self):
        """Resume scan from pause (clear pause_event, resume process, update UI)."""
        try:
            if not getattr(self, "scanning", False):
                self._log("ℹ️ Scan is not running.")
                return
            if not (getattr(self, "paused", False) or (hasattr(self, "pause_event") and self.pause_event.is_set())):
                self._log("ℹ️ Not paused.")
                return
    
            if hasattr(self, "pause_event"):
                self.pause_event.clear()
            self.paused = False
    
            # ادامهٔ پروسس
            try:
                proc = getattr(self, "process", None)
                if proc and proc.poll() is None:
                    psutil.Process(proc.pid).resume()
            except Exception as ex:
                self._err(f"resume resume-proc: {ex}")
    
            # UI
            try:
                if hasattr(self, "lbl_status"): self.lbl_status.setText("🟢 STATUS: RUNNING")
                if hasattr(self, "btn_toggle"): self.btn_toggle.setText("⏸ Pause")
                if hasattr(self, "btn_stop"):   self.btn_stop.setText("⏸ Pause")  # سازگاری
            except Exception:
                pass
            
            self._log("▶️ Resumed.")
        except Exception as ex:
            self._err(f"resume_scan: {ex}")
    
    # =======================================================================================
    # -------------------------------------- HARD STOP --------------------------------------
    def stop_scan_hard(self):
        """Immediate hard stop: set stop_event, clear pause, kill process, join thread, update UI."""
        try:
            # سیگنال‌های توقف
            if hasattr(self, "stop_event"):  self.stop_event.set()
            if hasattr(self, "pause_event"): self.pause_event.clear()
            self.paused = False

            # --- پیش از کشتن پروسس، تلاش برای ذخیره‌ی موقعیت فعلی (در حافظه)
            cur_part = int(getattr(self, "current_part", 0) or 0)
            cur_pos_int = getattr(self, "current_pos_int", None)  # پارسر خروجی اگر مقدار می‌دهد

            # کشتن پروسس فعال
            try:
                proc = getattr(self, "process", None)
                if proc and proc.poll() is None:
                    self._kill_process_tree(proc.pid, timeout=1.5)
            except Exception as ex:
                self._err(f"kill tree: {ex}")

            # منتظر جمع شدن نخ
            th = getattr(self, "scan_thread", None)
            if th and th.is_alive():
                try: th.join(timeout=2.0)
                except Exception: pass

            self.scanning = False

            # --- اطمینان از وجود ستون‌ها (ایمن)
            try:
                if hasattr(self, "_ensure_resume_columns"):
                    self._ensure_resume_columns()
            except Exception as ex:
                self._err(f"_ensure_resume_columns@hardstop: {ex}")

            # --- اگر cur_pos_int نداشتیم، از DB (parts) بازیابی کن
            if cur_pos_int is None and cur_part > 0:
                try:
                    import sqlite3
                    with sqlite3.connect(self.db_path) as conn:
                        c = conn.cursor()
                        row = c.execute("SELECT last_pos_hex, start_hex FROM parts WHERE part_index=?",
                                        (cur_part,)).fetchone()
                        if row:
                            lastp, startp = row[0], row[1]
                            if lastp:   cur_pos_int = int(lastp, 16)
                            elif startp: cur_pos_int = int(startp, 16)
                except Exception:
                    pass

            # --- ثبت رزوم: last_part، resume_same_part=1، current_pos_hex (اگر داریم)
            try:
                import sqlite3
                with sqlite3.connect(self.db_path) as conn:
                    c = conn.cursor()
                    c.execute("INSERT OR IGNORE INTO progress (id,last_part) VALUES (1, ?)", (int(cur_part or 0),))
                    c.execute("UPDATE progress SET last_part=?, resume_same_part=1 WHERE id=1", (int(cur_part or 0),))
                    if cur_pos_int is not None:
                        cur_hex = format(int(cur_pos_int), '064x').upper()
                        c.execute("UPDATE progress SET current_pos_hex=? WHERE id=1", (cur_hex,))
                    conn.commit()
            except Exception as ex:
                self._err(f"resume-save@hardstop: {ex}")

            # UI
            try:
                if hasattr(self, "lbl_status"): self.lbl_status.setText("🔴 STATUS: STOPPED")
                if hasattr(self, "btn_toggle"): self.btn_toggle.setText("⏸ Pause")
                if hasattr(self, "btn_stop"):   self.btn_stop.setText("⏸ Pause")  # سازگاری
            except Exception:
                pass

            # ذخیره/بکاپ
            try: self._save_progress()
            except Exception: pass
            try:
                if hasattr(self, "_backup_db"): self._backup_db(min_interval=0.0)
            except Exception: pass

            self._log(f"⛔ Hard stop. (resume_same_part=1, last_part={cur_part}"
                    f"{', pos='+format(int(cur_pos_int), '064x').upper() if cur_pos_int is not None else ''})")

        except Exception as ex:
            self._err(f"stop_scan_hard: {ex}")
    
    # -------------------------------------------------------------------------
    def on_click_pause_resume(self):
        """Toggle pause/resume with one button."""
        if not getattr(self, "scanning", False):
            self.start_scan(); return
        if getattr(self, "paused", False) or (hasattr(self,"pause_event") and self.pause_event.is_set()):
            self.resume_scan()
            try:
                if hasattr(self, "btn_toggle"): self.btn_toggle.setText("⏸ Pause")
                if hasattr(self, "btn_stop"):   self.btn_stop.setText("⏸ Pause")  # سازگاری
            except Exception: pass
        else:
            self.pause_scan()
            try:
                if hasattr(self, "btn_toggle"): self.btn_toggle.setText("▶️ Resume")
                if hasattr(self, "btn_stop"):   self.btn_stop.setText("▶️ Resume")  # سازگاری
            except Exception: pass
    
    # ==========================================================================
    def reset_scan(self):
        if getattr(self, "scanning", False):
            try:
                QMessageBox.warning(self, "Busy", "اول اسکن را متوقف کن.")
            except Exception:
                pass
            return
    
        # Hard-Stop ایمن (اگر چیزی نیمه‌کاره مانده)
        try:
            self.stop_scan_hard()   # ⬅️ قبلاً اشتباهاً _hard_stop فراخوانی شده بود
        except Exception:
            pass
        
        # بکاپ قبل از حذف
        try:
            if hasattr(self, "_backup_db"):
                self._backup_db(min_interval=0.0)
        except Exception:
            pass
        
        try:
            if getattr(self, "db_path", None) and os.path.exists(self.db_path):
                bak = self.db_path.replace(".db", f"_bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")
                try:
                    shutil.copyfile(self.db_path, bak)
                except Exception:
                    pass
                os.remove(self.db_path)
        except Exception as ex:
            self._err(f"reset_scan db cleanup: {ex}")
    
        self._init_db()
        self.current_part = 0
        self.loop_count = 0
        self.total_keys = 0
        self.part_keys = 0
        self.elapsed_total_seconds_before = 0.0
        self._ensure_parts_table()
        self._log("♻️ Scan reset (DB recreated).")

#=========================================================================
    def _ensure_resume_columns(self):
        import sqlite3
        try:
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            cols = {r[1] for r in c.execute("PRAGMA table_info(progress)").fetchall()}
            if "resume_same_part" not in cols:
                c.execute("ALTER TABLE progress ADD COLUMN resume_same_part INTEGER DEFAULT 0")
            if "current_pos_hex" not in cols:
                c.execute("ALTER TABLE progress ADD COLUMN current_pos_hex TEXT")
            conn.commit()
        except Exception as ex:
            try: self._err(f"_ensure_resume_columns: {ex}")
            except: pass
        finally:
            try: conn.close()
            except: pass

#==========================================================================
#           RESET PARTS FOR NEW LOOPS
#==========================================================================
    def _reset_parts_for_new_loop(self, loop_idx:int):
        try:
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            c.execute("UPDATE parts SET done=0, reason=?", (f"loop_{loop_idx}_start",))
            conn.commit(); conn.close()
        except Exception as ex:
            self._err(f"_reset_parts_for_new_loop: {ex}")

#==========================================================================
#               CORE SCANNING LOOP (UPDATED - supports custom parts list)
#==========================================================================
    def _scan_loop(self):
        """لوپ اسکن با Resume واقعی و شمارش لوپ بر اساس start_loop.
        Supports: self._use_custom_parts and self._custom_parts_list (built in start_scan()).
        """
        try:
            # --- آماده‌سازی تعداد پارت‌ها -----------------------------------
            total_parts = 0
            try:
                # if custom parts are in use, prefer those
                if getattr(self, "_use_custom_parts", False) and hasattr(self, "_custom_parts_list") and self._custom_parts_list:
                    total_parts = len(self._custom_parts_list)
                else:
                    # try DB count first (parts table)
                    with sqlite3.connect(self.db_path, timeout=3) as conn:
                        c = conn.cursor()
                        c.execute("SELECT COUNT(*) FROM parts")
                        row = c.fetchone()
                        total_parts = (row[0] if row else 0) or int(self.parts_spin.value())
            except Exception as ex:
                # fallback to parts_spin if anything fails
                self._err(f"_scan_loop init: {ex}")
                try:
                    if getattr(self, "_use_custom_parts", False) and hasattr(self, "_custom_parts_list") and self._custom_parts_list:
                        total_parts = len(self._custom_parts_list)
                    else:
                        total_parts = int(self.parts_spin.value())
                except Exception:
                    total_parts = int(getattr(self, "parts_spin", 1) or 1)

            # --- آماده‌سازی کنترل لوپ‌ها -----------------------------------
            loops_limit = 0
            try:
                if hasattr(self, "max_loops_spin"):
                    loops_limit = int(self.max_loops_spin.value() or 0)
                else:
                    loops_limit = int(getattr(self, "max_loops", 0) or 0)
            except Exception:
                loops_limit = 0

            # شروع از state ذخیره‌شده
            loop_idx = int(getattr(self, "loop_count", 0) or 0)
            self.current_loop = self.start_loop + loop_idx   # 🔹 لوپ واقعی
            last_part_idx = None

            while not (hasattr(self, "stop_event") and self.stop_event.is_set()):
                # --- احترام به Pause ------------------------------------
                while getattr(self, "paused", False) or (hasattr(self, "pause_event") and self.pause_event.is_set()):
                    try:
                        if hasattr(self, "lbl_status"):
                            self.lbl_status.setText("⏸ STATUS: PAUSED")
                    except Exception:
                        pass
                    time.sleep(0.1)
                    if hasattr(self, "stop_event") and self.stop_event.is_set():
                        break
                if hasattr(self, "stop_event") and self.stop_event.is_set():
                    break

                # --- لیست پارت‌های انجام‌نشده -----------------------------
                try:
                    undone = []
                    # prefer DB _undone_parts() if using parts table; otherwise compute from custom list
                    try:
                        undone = self._undone_parts() or []
                    except Exception as ex:
                        self._err(f"_undone_parts failed (falling back): {ex}")
                        # fallback: list indices 1..total_parts and exclude done ones
                        undone = []
                        for pi in range(1, int(total_parts) + 1):
                            try:
                                if not self._is_part_done(pi):
                                    undone.append(pi)
                            except Exception:
                                undone.append(pi)
                except Exception as ex:
                    self._err(f"_scan_loop undone prepare failed: {ex}")
                    undone = []

                if not undone:
                    # ✅ همه پارت‌ها انجام شدند → شروع لوپ جدید
                    loop_idx += 1
                    self.loop_count = loop_idx
                    self.current_loop = self.start_loop + self.loop_count - 1  # 🔹 شماره واقعی

                    if loops_limit > 0 and loop_idx > loops_limit:
                        self._log("✅ Max loops reached. Stopping.")
                        break

                    # UI: نمایش لوپ
                    try:
                        if hasattr(self, "lbl_loops"):
                            lim = ("∞" if loops_limit == 0 else str(loops_limit))
                            self.lbl_loops.setText(f"🔁 LOOPS: {self.current_loop} / {lim}")
                    except Exception:
                        pass

                    # ثبت وضعیت لوپ جدید
                    try:
                        with sqlite3.connect(self.db_path) as conn:
                            c = conn.cursor()
                            c.execute("""
                                UPDATE progress
                                SET loop_count=?, start_loop=?, updated_at=datetime('now')
                                WHERE id=1
                            """, (self.loop_count, self.start_loop))
                            conn.commit()
                    except Exception as ex:
                        self._err(f"loop increment save failed: {ex}")

                    # پارت‌ها را برای لوپ بعدی seed/reset کن
                    try:
                        self._reset_parts_for_new_loop(loop_idx)
                    except Exception as ex:
                        self._err(f"_reset_parts_for_new_loop({loop_idx}) failed: {ex}")

                    # ترتیب کل پارت‌ها
                    try:
                        part_order = self._make_part_order(total_parts)
                    except Exception as ex:
                        self._err(f"_make_part_order failed: {ex}")
                        part_order = list(range(1, int(total_parts) + 1))
                else:
                    # ✅ ادامه‌ی همین لوپ
                    if self.loop_count == 0:
                        self.loop_count = 1
                    try:
                        part_order = self._make_part_order_from_list(undone)
                    except Exception as ex:
                        self._err(f"_make_part_order_from_list failed: {ex}")
                        part_order = list(undone)

                # --- اجرای پارت‌ها ---------------------------------------
                for pi in part_order:
                    if hasattr(self, "stop_event") and self.stop_event.is_set():
                        break

                    # اگر همین لحظه پارت تیک خورد، رد شو
                    try:
                        if self._is_part_done(pi):
                            self._log(f"⏭ Part {pi} already done. Skipping.")
                            continue
                    except Exception as ex:
                        self._err(f"_is_part_done({pi}) failed: {ex}")

                    # مشخصات پارت: سعی کن از _get_part_range استفاده کنی، در غیر این صورت از custom list بردار
                    rng = None
                    try:
                        try:
                            rng = self._get_part_range(pi)
                        except Exception:
                            rng = None
                        if not rng and getattr(self, "_use_custom_parts", False) and hasattr(self, "_custom_parts_list"):
                            idx = int(pi) - 1
                            if 0 <= idx < len(self._custom_parts_list):
                                a_hex, b_hex = self._custom_parts_list[idx]
                                rng = (a_hex, b_hex)
                    except Exception as ex:
                        self._err(f"_get_part_range({pi}) fallback failed: {ex}")
                        rng = None

                    if not rng:
                        self._err(f"No range for part {pi}; skipping.")
                        continue
                    a, b = rng

                    # ریست یا ادامه part_keys
                    reset_part_keys = True
                    try:
                        if hasattr(self, "_get_part_status"):
                            st = self._get_part_status(pi)
                            if str(st).upper() == "IN_PROGRESS" and last_part_idx == pi:
                                reset_part_keys = False
                    except Exception:
                        pass

                    self.current_part = pi
                    if reset_part_keys:
                        self.part_keys = 0

                    # ذخیره state
                    try:
                        self._save_progress()
                    except Exception:
                        pass

                    # UI: Running
                    try:
                        if hasattr(self, "lbl_status"):
                            self.lbl_status.setText(f"🟢 STATUS: RUNNING (Loop {self.current_loop}, Part {pi})")
                    except Exception:
                        pass

                    # اجرای پارت
                    try:
                        ok = self._run_single_part(pi, a, b, minutes=int(self.part_minutes))
                    except Exception as ex:
                        self._err(f"_run_single_part({pi}) failed: {ex}")
                        ok = False

                    last_part_idx = pi

                    if not ok and hasattr(self, "stop_event") and self.stop_event.is_set():
                        break

                    if getattr(self, "paused", False) or (hasattr(self, "pause_event") and self.pause_event.is_set()):
                        try:
                            self._save_progress()
                        except Exception:
                            pass

                time.sleep(0.01)

            # --- خروج تمیز ---------------------------------------------
            self.scanning = False
            try:
                if hasattr(self, "lbl_status"):
                    self.lbl_status.setText("🔴 STATUS: STOPPED")
            except Exception:
                pass
            try:
                self._save_progress()
            except Exception:
                pass
            self._log("⛔ Scan stopped")

        except Exception as e:
            self.scanning = False
            try:
                if hasattr(self, "lbl_status"):
                    self.lbl_status.setText("🔴 STATUS: ERROR")
            except Exception:
                pass
            try:
                self._save_progress()
            except Exception:
                pass
            self._err(f"Scan loop error: {e}")

#========================================================================
#           GET PART RANGE
#===========================================================================    
    def _get_part_range(self, part_idx):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT start_hex,end_hex FROM parts WHERE part_index=?",     (part_idx,))
            row = c.fetchone()
            conn.close()

            if row and row[0] and row[1]:
                # اطمینان از اینکه end >= start
                try:
                    if int(row[1], 16) < int(row[0], 16):
                        return row[0], row[0]  # فیکس: اگر خراب باشه، فقط تک مقدار
                except Exception:
                    pass
                return row[0], row[1]

            # ✅ fallback درست: از _split_keyspace بدون پارامتر استفاده کن
            try:
                ranges = self._split_keyspace()
                if 1 <= part_idx <= len(ranges):
                    return ranges[part_idx-1]
            except Exception:
                pass

            return None

        except Exception as ex:
            self._err(f"_get_part_range: {ex}")
            return None

#==========================================================================
#           IS PART DONE
#==========================================================================
    def _is_part_done(self, part_idx):
        try:
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            c.execute("SELECT done FROM parts WHERE part_index=?", (part_idx,))
            row = c.fetchone(); conn.close()
            return bool(row and int(row[0]) == 1)
        except Exception as ex:
            self._err(f"_is_part_done: {ex}")
            return False

#==================================================================================
# ************************  Part Runner ************************************
#=================================================================================
    def _run_single_part(self, part_idx, start_hex, end_hex, minutes=3):
        """
        اجرای یک پارت واحد با مدیریت توقف/وقفه/timeout و ثبت کامل در DB.
        """
    
        import os, re, time, sqlite3, subprocess, psutil
        from datetime import datetime
    
        # --- کمک‌کننده‌ها
        def _try_parse_bit_or_hex(x):
            s = str(x).strip()
            if re.fullmatch(r'\d{1,3}', s):
                try:
                    bi = int(s, 10)
                    if 1 <= bi <= 256:
                        return True, bi
                except Exception:
                    pass
            s2 = s.lower().lstrip('0x')
            if re.fullmatch(r'[0-9a-fA-F]+', s2):
                try:
                    val = int(s2, 16)
                    return False, val
                except Exception:
                    pass
            raise ValueError(f"Cannot parse bit/hex from '{x}'")
    
        def _bit_to_range(start_bit: int, end_bit: int):
            if end_bit < start_bit:
                raise ValueError("end_bit must be >= start_bit")
            start_int = 1 << (start_bit - 1)
            end_int = (1 << end_bit) - 1
            return start_int, end_int
    
        # 🔀 Random counter: شمارنده‌ی پارت‌های رندوم
        if getattr(self, "_random_enabled", False):
            if not hasattr(self, "_random_parts_done"):
                self._random_parts_done = 0
            self._random_parts_done += 1
            self._refresh_total_part_rnd()

        # ⬇️ ذخیره مقدار در DB
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            c.execute("UPDATE progress SET random_parts_done=? WHERE id=1", (self._random_parts_done,))
            conn.commit(); conn.close()
        except Exception as ex:
            self._err(f"save random_parts_done: {ex}")

    
        try:
            # تشخیص حالت بیت یا هگز
            is_bit_a, val_a = _try_parse_bit_or_hex(start_hex)
            is_bit_b, val_b = _try_parse_bit_or_hex(end_hex)
            if is_bit_a and is_bit_b:
                start_int, end_int = _bit_to_range(int(val_a), int(val_b))
            else:
                if is_bit_a != is_bit_b:
                    raise ValueError("Both start and end must be bits or both hex.")
                start_int = int(val_a)
                end_int = int(val_b)
        except Exception as ex:
            self._err(f"_run_single_part({part_idx}) bad keyspace args: {ex}")
            return False
    
        # پارت جاری
        self.current_part = int(part_idx)
        self.part_start_int = int(start_int)
    
        # نمایش HEX
        disp_a = format(start_int, '064x').upper()
        disp_b = format(end_int,   '064x').upper()
        a, b   = disp_a, disp_b  
    
        # ثبت در DB
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("INSERT OR IGNORE INTO progress (id,last_part) VALUES (1,?)", (int(part_idx),))
                c.execute("UPDATE progress SET last_part=? WHERE id=1", (int(part_idx),))
                conn.commit()
        except Exception:
            pass
    
        # لاگ
        self._log(f"▶️ PART {part_idx} → [{disp_a} .. {disp_b}] for {minutes} min")
    
        self.start_part_time = time.time()
        deadline = self.start_part_time + minutes * 60
        self._last_part_completed_flag = False
        self._part_first_total_seen = False
    
        if not hasattr(self, "part_key_current"):
            self.part_key_current = 0
        if not hasattr(self, "part_keys"):
            self.part_keys = 0
        try:
            if hasattr(self, "lbl_part_keys"):
                self.lbl_part_keys.setText(f"🗝 PART KEY: {int(self.part_keys):,}")
        except Exception:
            pass
    
        #------------
        # آغاز پارت در DB
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("UPDATE parts SET start_time=?, reason=? WHERE part_index=?",
                        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "running", int(part_idx)))
                conn.commit()
            try: self._backup_db()
            except Exception: pass
        except Exception as ex:
            self._err(f"parts-start update: {ex}")
        # فایل اجرایی
        exe = self._resolve_bitcrack()
        if not exe:
            self._err("DEMO.exe not found. Stop.")
            if hasattr(self, "stop_event"): self.stop_event.set()
            return False
        # فایل هدف‌ها
        targets = (self.input_file.text() if hasattr(self, "input_file") else "") or ""
        targets = targets.strip()
        if targets and not os.path.isabs(targets):
            targets = os.path.join(self.base_dir, targets)
        if not targets or not os.path.exists(targets):
            self._err("Targets .txt تنظیم/یافت نشد؛ اجرای این پارت متوقف شد.")
            return False
        # سوئیچ‌ها و args
        cli = self._detect_cli() or {}
        args = [exe]
        args += [cli.get('keyspace', '--keyspace'), f"{a}:{b}"]
        look = (self.look_mode.currentText() if hasattr(self, "look_mode") else "compressed")
        if str(look).lower() == "compressed":
            args.append(cli.get('compressed', '--compressed'))
        else:
            args.append(cli.get('uncompressed', '--uncompressed'))
        dev = self._gpu_index_text()
        if dev:
            args += [cli.get('device', '--device'), dev]
        def _add_opt(opt_key, val):
            if val is None: return
            sval = str(val).strip()
            if not sval: return
            args.extend([cli.get(opt_key, f"--{opt_key}"), sval])
        _add_opt('blocks',  getattr(self.block,  "currentText", lambda: "")())
        _add_opt('threads', getattr(self.thread, "currentText", lambda: "")())
        _add_opt('points',  getattr(self.points, "currentText", lambda: "")())
        _add_opt('stride',  (self.stride.text() if hasattr(self, "stride") else "1") or "1")
        args += [cli.get('in', '--in'), targets]
        popen_kwargs = {"cwd": self.base_dir}
        if os.name == "nt":
            try: popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            except Exception: pass
        # اجرا و مانیتورینگ (باقی منطق مشابه نسخهٔ اصلی شما)
        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1, **popen_kwargs)
            self.process = proc
        except Exception as ex:
            self._err(f"spawn error: {ex}")
            return False
        quick_failures = 0
        reason = "unknown"
        _last_pos_save_t = 0.0
        try:
            while True:
                # Pause
                if hasattr(self, "pause_event") and self.pause_event.is_set():
                    pause_t0 = time.time()
                    try:
                        if proc and proc.poll() is None:
                            psutil.Process(proc.pid).suspend()
                    except Exception: pass
                    try:
                        if hasattr(self, "lbl_status"):
                            self.lbl_status.setText("⏸ STATUS: PAUSED")
                    except Exception: pass
                    while self.pause_event.is_set() and not (hasattr(self, "stop_event") and self.stop_event.is_set()):
                        try:
                            now_t = time.time()
                            curpos = getattr(self, "current_pos_int", None)
                            if curpos is not None and now_t - _last_pos_save_t >= 2.0:
                                _last_pos_save_t = now_t
                                with sqlite3.connect(self.db_path) as conn:
                                    c = conn.cursor()
                                    c.execute("UPDATE progress SET current_pos_hex=? WHERE id=1",
                                            (format(int(curpos), '064x').upper(),))
                                    conn.commit()
                        except Exception: pass
                        try: self._backup_db()
                        except Exception: pass
                        time.sleep(0.2)
                    if hasattr(self, "stop_event") and self.stop_event.is_set():
                        reason = "stopped"; break
                    paused_for = time.time() - pause_t0
                    deadline += paused_for
                    try:
                        if getattr(self, "start_part_time", None):
                            self.start_part_time += paused_for
                    except Exception: pass
                    try:
                        if proc and proc.poll() is None:
                            psutil.Process(proc.pid).resume()
                    except Exception: pass
                    try:
                        if hasattr(self, "lbl_status"):
                            self.lbl_status.setText("🟢 STATUS: RUNNING")
                    except Exception: pass
                    continue
                # Stop
                if hasattr(self, "stop_event") and self.stop_event.is_set():
                    reason = "stopped"; break
                now = time.time()
                if now >= deadline:
                    reason = "timeout"; break
                # Throttle save pos
                try:
                    if now - _last_pos_save_t >= 2.0:
                        _last_pos_save_t = now
                        curpos = getattr(self, "current_pos_int", None)
                        if curpos is not None:
                            with sqlite3.connect(self.db_path) as conn:
                                c = conn.cursor()
                                c.execute("UPDATE progress SET current_pos_hex=? WHERE id=1",
                                        (format(int(curpos), '064x').upper(),))
                                conn.commit()
                except Exception:
                    pass
                try: self._backup_db()
                except Exception: pass
                line = proc.stdout.readline()
                if line == '' and proc.poll() is not None:
                    # Quick respawn logic (keepalive)
                    if (now - self.start_part_time) < 1.0 and quick_failures < 2:
                        quick_failures += 1
                        self._log("↺ Restarting DEMO for this part (keepalive).")
                        try:
                            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                                    text=True, bufsize=1, **popen_kwargs)
                            self.process = proc
                            self.start_part_time = time.time()
                            deadline = self.start_part_time + minutes * 60
                            continue
                        except Exception as ex:
                            self._err(f"respawn error: {ex}")
                    rc = proc.returncode
                    reason = f"exit({rc})"
                    break
                if line:
                    sline = line.strip()
                    try:
                        self._handle_bitcrack_output(part_idx, sline)
                    except Exception as ex:
                        self._err(f"_handle_bitcrack_output: {ex}")
                    # fallback: استخراج total از لاگ و ساخت current_pos_int
                    try:
                        m = re.search(r'\(([\d,]+)\s+total\)', sline)
                        if m:
                            tot = int(m.group(1).replace(',', ''))
                            self.tested_total = tot
                            base = int(getattr(self, "part_start_int", 0) or 0)
                            self.current_pos_int = base + tot
                    except Exception:
                        pass
                    try:
                        if hasattr(self, "_maybe_extract_gpu_from_bitcrack_line"):
                            self._maybe_extract_gpu_from_bitcrack_line(sline)
                    except Exception:
                        pass
                # GPU Util Throttle
                try:
                    gpu_util = int(self.gpu_util.value()) if hasattr(self, "gpu_util") else 100
                except Exception:
                    gpu_util = 100
                if 10 <= gpu_util < 100:
                    busy_ratio = gpu_util / 100.0
                    sleep_time = (1.0 - busy_ratio) * 0.05
                    if sleep_time > 0:
                        time.sleep(sleep_time)
        finally:
            # پایان پروسه
            try:
                if proc and proc.poll() is None:
                    proc.terminate()
                    try: proc.wait(timeout=2)
                    except Exception:
                        try: proc.kill()
                        except Exception: pass
            except Exception: pass
            self.process = None
        # مدت زمان این پارت
        elapsed = time.time() - self.start_part_time
        # 🔹 ثبت last_part در DB
        now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("INSERT OR IGNORE INTO progress (id) VALUES (1)")
                try:
                    c.execute("UPDATE progress SET last_part=?, updated_at=? WHERE id=1", (int(part_idx), now_ts))
                except Exception:
                    c.execute("UPDATE progress SET last_part=? WHERE id=1", (int(part_idx),))
                conn.commit()
        except Exception as ex:
            self._err(f"progress-anchor upsert: {ex}")
        rc = getattr(proc, "returncode", None)
        done_flag = 1 if (self._last_part_completed_flag and reason not in ("timeout", "stopped")) else 0
        last_total = int(getattr(self, "last_total_seen", getattr(self, "tested_total", 0)) or 0)
        if self.tested_baseline_part is None:
            delta_processed = 0
        else:
            delta_processed = max(0, last_total - int(self.tested_baseline_part or 0))
        self.part_key_current = int(delta_processed)
        try:
            if hasattr(self, "lbl_part_keys"):
                self.lbl_part_keys.setText(f"🗝 PART KEY: {int(self.part_key_current):,}")
        except Exception: pass
        # پایان پارت در DB
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                c.execute("""
                    UPDATE parts
                    SET done = CASE WHEN ?=1 THEN 1 ELSE done END,
                        elapsed_in_part   = COALESCE(elapsed_in_part,0) + ?,
                        part_keys         = COALESCE(part_keys,0)       + ?,
                        processed_in_part = COALESCE(processed_in_part,0) + ?,
                        end_time          = ?,
                        reason            = ?
                    WHERE part_index=?
                """, (int(done_flag),
                    float(elapsed),
                    int(getattr(self, 'part_keys', 0) or 0),
                    int(self.part_key_current or 0),
                    now_ts,
                    str(reason or "done"),
                    int(part_idx)))
                conn.commit()
            try: self._backup_db()
            except Exception: pass
        except Exception as ex:
            self._err(f"parts-end update: {ex}")
        # جمع سشن += Δ همین پارت
        try:
            self.total_part_key = int(getattr(self, "total_part_key", 0)) + int(self.part_key_current or 0)
        except Exception: pass
        # ✅ پاک‌سازی/ثبت رزوم در پایان
        try:
            with sqlite3.connect(self.db_path) as conn:
                c = conn.cursor()
                if done_flag == 1:
                    c.execute("UPDATE progress SET current_pos_hex=NULL WHERE id=1")
                else:
                    curpos = getattr(self, "current_pos_int", None)
                    if curpos is not None:
                        c.execute("UPDATE progress SET current_pos_hex=? WHERE id=1",
                                (format(int(curpos), '064x').upper(),))
                conn.commit()
        except Exception as ex:
            self._err(f"final resume save/clear: {ex}")
        # اسنپ‌شات
        try:
            self._save_progress()
        except Exception as ex:
            self._err(f"_save_progress (at part end): {ex}")
        self._log(f"✅ PART {part_idx} finished. Found={int(getattr(self, 'part_keys', 0) or 0):,}, "
                f"TestedΔ={int(self.part_key_current or 0):,}, Elapsed={int(elapsed)}s, "
                f"Done={done_flag}, Reason={reason}")
    #------------    
        try:
            if getattr(self, "_rebuild_remaining_after_part", False):
                undone_now = self._undone_parts()
                self._current_part_queue = self._make_part_order_from_list(undone_now)
                self._part_queue_idx = 0
                self._rebuild_remaining_after_part = False
                self._log(f"🔁 Remaining queue rebuilt (Random: {'ON' if self._random_enabled else 'OFF'}).")
        except Exception as ex:
            self._err(f"rebuild-remaining: {ex}")
    
        return not (hasattr(self, "stop_event") and self.stop_event.is_set())

#==============================================================================
#           HANDLE BITCRACK OUTPUT
#==============================================================================================
    def _handle_bitcrack_output(self, part_idx, line):
        import re
        try:
            if not line:
                return
            low = line.lower()

            # ---- حالت 1: فرمت دو-خطی (Address: ... / Private key: ...)
            m_addr = re.search(r'\bAddress:\s+((?:bc1[0-9a-z]{11,71})|(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}))', line, re.I)
            if m_addr:
                self._pending_addr = m_addr.group(1).strip()

            m_pk = re.search(r'\bPrivate\s*key:\s*([0-9A-Fa-f]{64}|\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b)', line, re.I)
            if m_pk:
                self._pending_pk = m_pk.group(1).strip()

            # اگر هر دو داریم، ثبت Found
            if getattr(self, "_pending_addr", None) or getattr(self, "_pending_pk", None):
                try:
                    self._try_flush_pending_found(part_idx)
                except Exception as ex:
                    # از دست نره
                    try: self._append_log_line(f"_try_flush_pending_found: {ex}", "ERROR")
                    except: pass

            # ---- حالت 2: تک‌خطه — آدرس + کلید در یک خط
            if not (m_addr or m_pk):
                try:
                    # اگر در کدت regex سراسری آدرس داری
                    if 'ADDR_RE' in globals():
                        m_inline_addr = ADDR_RE.search(line)
                        addr_val = m_inline_addr.group(1) if m_inline_addr else None
                    else:
                        m_inline_addr = re.search(r'(bc1[0-9a-z]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})', line)
                        addr_val = m_inline_addr.group(1) if m_inline_addr else None

                    m_inline_pk = re.search(r'\b[0-9A-Fa-f]{64}\b|\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b', line)
                    if addr_val and m_inline_pk:
                        self._pending_addr = addr_val
                        self._pending_pk   = m_inline_pk.group(0)
                        self._try_flush_pending_found(part_idx)
                except Exception:
                    pass

            # ---- SPEED: 84.20 MKey/s یا 1.23 GKey/s
            m_sp = re.search(r'([\d.]+)\s*([GMK])?Key/s', line, re.I)
            if m_sp and hasattr(self, "lbl_speed"):
                try:
                    val = float(m_sp.group(1)); unit = (m_sp.group(2) or 'M').upper()
                    if unit == 'G':   val *= 1000.0
                    elif unit == 'K': val /= 1000.0
                    self.lbl_speed.setText(f"⚡ SPEED: {val:.2f} MKey/s")
                except Exception:
                    pass

            # ---- TARGETS: "150 targets"
            m_tg = re.search(r'\b(\d+)\s+targets\b', line, re.I)
            if m_tg:
                try:
                    self.targets_count = int(m_tg.group(1))
                    if hasattr(self, "lbl_targets"):
                        self.lbl_targets.setText(f"🎯 TARGETS: {self.targets_count}")
                except Exception:
                    pass

            # ---- Starting/Ending at (برای تنظیم دقیق part_start_int هنگام رزوم/شروع)
            try:
                m_start = re.search(r'\bStarting at:\s*([0-9A-Fa-f]{64})', line)
                if m_start:
                    self.part_start_int = int(m_start.group(1), 16)
            except Exception:
                pass
            # (Ending at لازم نیست برای رزوم؛ فقط اطلاعاتی است.)

            # ---- TESTED TOTAL (… total)  → ساخت current_pos_int = part_start_int + total
            m_tt = re.search(r'\(([0-9,]+)\s+total\)', line, re.I) or re.search(r'\btotal\b\D*([0-9,]+)', line, re.I)
            if m_tt:
                try:
                    new_total = int(m_tt.group(1).replace(',', ''))
                    # baseline/Δ پارت
                    if (not getattr(self, "_part_first_total_seen", False)) or \
                    (getattr(self, "tested_baseline_part", None) is None) or \
                    (new_total < int(getattr(self, "last_total_seen", 0) or 0)):
                        self.tested_baseline_part = new_total
                        self._part_first_total_seen = True

                    self.last_total_seen = new_total
                    self.tested_total = new_total

                    pkc = max(0, new_total - int(self.tested_baseline_part or 0))
                    self.part_key_current = pkc
                    if hasattr(self, "lbl_part_keys"):
                        self.lbl_part_keys.setText(f"🗝 PART KEY: {pkc:,}")

                    # مجموع سشن = جمع پارت‌های قبلی + Δ پارت جاری (برای UI)
                    session_live_total = int(getattr(self, "total_part_key", 0) or 0) + int(self.part_key_current or 0)
                    if hasattr(self, "lbl_tested"):
                        self.lbl_tested.setText(f"🧮 TESTED TOTAL: {session_live_total:,}")

                    # موقعیت فعلی برای رزوم سخت:
                    base = int(getattr(self, "part_start_int", 0) or 0)
                    self.current_pos_int = base + new_total
                except Exception:
                    pass

            # ---- GPU: فقط خطوط استارت CUDA را پارس کن (نه خط سرعت ترکیبی)
            if re.search(r'^\s*(CUDA device|Using CUDA device)', line, re.I):
                if hasattr(self, "_maybe_extract_gpu_from_bitcrack_line"):
                    try: self._maybe_extract_gpu_from_bitcrack_line(line)
                    except Exception: pass

            # ---- پایانِ کامل رنج (نشانهٔ تمام شدن پارت)
            if any(k in low for k in ("range exhausted", "finished", "complete", "end of range")):
                self._last_part_completed_flag = True

            # ---- لاگ/خطا
            if any(k in low for k in (" error", "usage", "unknown option", "invalid", "failed")):
                self._append_log_line(line, "ERROR")
            else:
                self._append_log_line(line, "OUT")

        except Exception as ex:
            try: self._append_log_line(f"_handle_bitcrack_output parse error: {ex}", "ERROR")
            except: pass

#===============================================================================================
#                  RESOLVE 
#=================================================================================================
    def _resolve_bitcrack(self):
        """مسیر اجرایی  را برمی‌گرداند؛ ابتدا از کنار فایل، سپس PATH."""
        cand = [
            os.path.join(self.base_dir, "DEMO.exe"),
            os.path.join(self.base_dir, BITCRACK_PATH_DEFAULT),
            "DEMO.exe", BITCRACK_PATH_DEFAULT
                        
        ]
        for p in cand:
            try:
                if os.path.exists(p):
                    return p
            except Exception:
                pass
        wb = shutil.which("DEMO.exe")
        if wb: return wb
    
        return None

#===============================================================================================
#       GPU INDEX TEXT
#==============================================================================================
    def _gpu_index_text(self):
        """متن انتخاب GPU (مثل '0, GeForce ...') را به ایندکس '0' تبدیل می‌کند."""
        try:
            txt = self.gpu_box.currentText() if hasattr(self, "gpu_box") else ""
            m = re.match(r'\s*(\d+)', txt or "")
            return m.group(1) if m else None
        except Exception:
            return None

#===============================================================================================
#           SAVE PROGRESS
#==============================================================================================
    def _save_progress(self):
       try:
           # اسکیمای progress را تضمین کن
           try: self._ensure_progress_schema()
           except Exception as ex: self._err(f"_ensure_progress_schema@save: {ex}") 
           conn = sqlite3.connect(self.db_path); c = conn.cursor()  
           # مقادیر فعلی
           last_part = int(getattr(self, "current_part", 0) or 0)
           loop_cnt  = int(getattr(self, "loop_count", 0) or 0)
           # tested_total = کل «total» گزارش‌شده توسط BitCrack (last_total_seen) یا همون tested_total داخلی
           tested    = int(getattr(self, "tested_total", getattr(self, "last_total_seen", 0)) or 0)
           total     = int(getattr(self, "total_keys", 0) or 0) 
           # elapsed_seconds (نام درست ستون) — elapsed_total_seconds_before + زمان جاری سشن
           elapsed = float(getattr(self, "elapsed_total_seconds_before", 0.0) or 0.0)
           if getattr(self, "scanning", False) and getattr(self, "start_range_time", None):
               try:
                   elapsed += (time.time() - float(self.start_range_time or 0))
               except Exception:
                   pass 
           # processed_total = مجموع تست‌شده‌ی سشن (part_accum + Δ پارت جاری)
           processed_total = int(getattr(self, "total_part_key", 0) or 0) + int(getattr(self, "part_key_current", 0) or 0)  
           now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")   
           # اطمینان از وجود ردیف
           c.execute("INSERT OR IGNORE INTO progress (id) VALUES (1)")  
           # به‌روزرسانی امن (last_part اگر 0 بود دست‌نزن)
           c.execute("""
               UPDATE progress
                  SET last_part = CASE WHEN ?<>0 THEN ? ELSE last_part END,
                      loop_count = ?,
                      tested_total = ?,
                      total_keys = ?,
                      elapsed_seconds = ?,
                      processed_total = ?,
                      updated_at = ?
                WHERE id=1
           """, (last_part, last_part, loop_cnt, tested, total, float(elapsed), processed_total, now))  
           conn.commit(); conn.close()
       except Exception as ex:
           self._err(f"_save_progress: {ex}")
                                                   
# =============================================================================================
#   SAVE FOUND
#=============================================================================================            
    def _save_found(self, part_idx: int, address: str, privkey: str) -> bool:
        """ذخیره Found با حذف تکراری‌ها. True = رکورد جدید درج شد."""
        try:
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            # تضمین ستون زمان
            c.execute("""
                CREATE TABLE IF NOT EXISTS found_keys(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    part_index INTEGER, address TEXT, privkey TEXT
                )
            """)
            cols = [r[1].lower() for r in c.execute("PRAGMA table_info(found_keys)")]
            if "timestamp" not in cols and "ts" not in cols:
                c.execute("ALTER TABLE found_keys ADD COLUMN timestamp TEXT")
            # شاخص یکتا (ممکنه قبلاً ساخته باشی)
            c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_found_addr_pk ON found_keys(address, privkey)")

            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # درجِ «OR IGNORE» تا تکراری‌ها خطا ندهند
            c.execute("""
                INSERT OR IGNORE INTO found_keys(part_index,address,privkey,timestamp)
                VALUES(?,?,?,?)
            """, (part_idx, address, privkey, now))
            inserted = (c.rowcount == 1)

            if inserted:
                # فقط اگر جدید بود، شمارنده‌های progress را بالا ببر
                c.execute("""
                    UPDATE progress
                    SET total_keys=COALESCE(total_keys,0)+1,
                        found_count=COALESCE(found_count,0)+1
                    WHERE id=1
                """)
            conn.commit(); conn.close()

            # اسپول به فایل‌های متنی داخل پوشهٔ found/ فقط اگر جدید بود
            if inserted:
                try:
                    fd = self.get_found_dir()
                    # همهٔ جفت‌ها (Address,PrivKey)
                    with open(os.path.join(fd, "found_pairs.txt"), "a", encoding="utf-8") as f:
                        f.write(f"{address},{privkey}\n")
                    # فقط آدرس‌ها (اگه خواستی جای دیگه مصرف کنی)
                    with open(os.path.join(fd, "found_addresses.txt"), "a", encoding="utf-8") as f:
                        f.write(f"{address}\n")
                    # JSONL برای اسکریپت‌ها
                    with open(os.path.join(fd, "found_keys.jsonl"), "a", encoding="utf-8") as f:
                        f.write(json.dumps({"part_index":part_idx,"address":address,"privkey":privkey,"ts":now}, ensure_ascii=False)+"\n")
                except Exception:
                    pass

            return inserted
        except Exception as ex:
            self._err(f"_save_found: {ex}")
            return False

#===============================================================================================
#       GET FOUND KEYS
#==============================================================================================
    def get_found_keys(self, limit=100):
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # چه ستون زمانی داریم؟
        cols = [r[1].lower() for r in c.execute("PRAGMA table_info(found_keys)")]
        if "ts" in cols and "timestamp" in cols:
            time_expr = "COALESCE(ts, timestamp, datetime('now')) AS ts"
        elif "ts" in cols:
            time_expr = "ts AS ts"
        elif "timestamp" in cols:
            time_expr = "timestamp AS ts"
        elif "created_at" in cols:
            time_expr = "created_at AS ts"
        else:
            time_expr = "datetime('now') AS ts"

        sql = f"""
            SELECT part_index, address, privkey, {time_expr}
            FROM found_keys
            ORDER BY id DESC
        """
        if isinstance(limit, int):
            sql += f" LIMIT {limit}"

        rows = [{"part_index": p, "address": a, "privkey": k, "ts": t}
                for (p, a, k, t) in c.execute(sql).fetchall()]
        conn.close()
        return rows

#===============================================================================================
#   TOTAL FOUND COUNT
#==============================================================================================
    def total_found_count(self) -> int:
        conn = sqlite3.connect(self.db_path); c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM found_keys"); n = int(c.fetchone()[0] or 0)
        conn.close(); return n
#===============================================================================================
#       PART FOUND COUNT
#==============================================================================================
    def part_found_count(self, part_idx:int) -> int:
        conn = sqlite3.connect(self.db_path); c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM found_keys WHERE part_index=?", (part_idx,))
        n = int(c.fetchone()[0] or 0); conn.close(); return n

#================================================================
#   SET GPU LABEL
#===============================================================
    def _set_gpu_label(self, text: str):
        """Safe setter برای لیبل GPU؛ هر کدومی که وجود داشت آپدیت می‌شود."""
        try:
            if hasattr(self, "lbl_gpu_line"):
                self.lbl_gpu_line.setText(f"🟢 GPU: {text if text.strip() else '—'}")
            elif hasattr(self, "lbl_gpu"):
                self.lbl_gpu.setText(f"🖥️ GPU : {text}")
            elif hasattr(self, "lbl_gpu_value"):
                self.lbl_gpu_value.setText(text)
            elif hasattr(self, "gpu_label"):
                self.gpu_label.setText(f"GPU: {text}")
            else:
                self._log(f"[GPU] {text}")
        except Exception:
            pass
#===============================================================================================
#       GPU QUERY FROM NVIDIA SMI
#==============================================================================================
    def _gpu_query_from_nvidia_smi(self, pick_index: int | None = None) -> dict | None:
        """خلاصهٔ وضعیت GPU از nvidia-smi؛ شامل mem.used/total, util, temp, fan, power, pstate, driver."""
        if shutil.which("nvidia-smi") is None:
            return None
        try:
            cmd = [
                "nvidia-smi",
                "--query-gpu=index,name,memory.used,memory.total,temperature.gpu,utilization.gpu,fan.speed,power.draw,pstate,driver_version",
                "--format=csv,noheader,nounits",
            ]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=2.5)
            lines = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
            if not lines:
                return None
            #---------------------------------------------------------------------------------------
            def _to_int(s):
                try: return int(float(s))
                except: return None

            items = []
            for ln in lines:
                parts = [p.strip() for p in ln.split(",")]
                if len(parts) < 10:
                    continue
                idx, name, mem_used, mem_total, temp, util, fan, power, pstate, drv = parts[:10]
                items.append({
                    "index": _to_int(idx),
                    "name": name,
                    "mem_used_mb": _to_int(mem_used),
                    "mem_mb": _to_int(mem_total),
                    "temp_c": _to_int(temp),
                    "util_pct": _to_int(util),
                    "fan_pct": _to_int(fan),
                    "power_w": _to_int(power),
                    "pstate": pstate,
                    "driver": drv,
                })
            if not items:
                return None
            if pick_index is not None:
                items = [x for x in items if x.get("index") == pick_index] or items
            return items[0]
        except Exception:
            return None

#===============================================================================================
#       COMPOSE GPU TXT
#==============================================================================================
    def _compose_gpu_text(self, info: dict | None) -> str:
        if not info:
            return "—"
        bits = []
        if info.get("name") and info.get("mem_mb") is not None:
            bits.append(f"{info['name']} ({info['mem_mb']:,}MB)")
        elif info.get("name"):
            bits.append(info["name"])
        if info.get("temp_c") is not None: bits.append(f"{info['temp_c']}°C")
        if info.get("util_pct") is not None: bits.append(f"{info['util_pct']}%")
        if info.get("pstate"): bits.append(info["pstate"])
        if info.get("driver"): bits.append(f"Driver {info['driver']}")
        return " | ".join(bits) if bits else "—"
#===============================================================================================
#       MAYBE EXTRACT GPU FROM BITCRACK LINE
#==============================================================================================
    def _maybe_extract_gpu_from_bitcrack_line(self, line: str):
        """
        اگر DEMO موقع استارت خط GPU چاپ کرد، کَش کن و همون‌جا لیبل را آپدیت کن.
        مثال‌ها:
          "CUDA device 0: NVIDIA GeForce RTX 3060 (12288 MB)"
          "Using CUDA device NVIDIA GeForce RTX 3080 with 10024 MB"
        """
        try:
            m = re.search(
                r"(?:CUDA device(?:\s+\d+:)?|Using CUDA device)\s*:?\s*(.+?)(?:\(|with)\s*([0-9]{3,6})\s*MB",
                line, re.I
            )
            if m:
                name = m.group(1).strip()
                mem  = int(m.group(2))
                txt = f"{name} ({mem:,}MB)"
                self.gpu_line = txt
                self._set_gpu_label(txt)
        except Exception:
            pass
#===============================================================================================
#       REFRESH GPU LABEL
#==============================================================================================
    def _refresh_gpu_label(self):
        # ایندکس انتخابی از ComboBox فعلی UI
        pick_index = None
        try:
            if hasattr(self, "gpu_box"):
                txt = self.gpu_box.currentText()
                m = re.match(r'(\d+)', txt)
                if m: pick_index = int(m.group(1))
        except Exception:
            pick_index = None

        info = self._gpu_query_from_nvidia_smi(pick_index)
        if info:
            txt = self._compose_gpu_text(info)
            self.gpu_line = txt
            self._set_gpu_label(txt)
            return
        # fallback به کش/لاگ
        txt = (getattr(self, "gpu_line", "") or "").strip()
        self._set_gpu_label(txt if txt else "—")
#===============================================================================================
# GPU QUERY FROM NVML
#==============================================================================================
    def _gpu_query_from_nvml(self, pick_index: int | None = None) -> dict | None:
        """NVML اگر در دسترس باشد، دقیق‌ترین داده‌ها را می‌دهد."""
        try:
            import pynvml as nv
            nv.nvmlInit()
            count = nv.nvmlDeviceGetCount()
            if count <= 0:
                nv.nvmlShutdown(); return None
            i = pick_index if (isinstance(pick_index, int) and 0 <= pick_index < count) else 0
            h = nv.nvmlDeviceGetHandleByIndex(i)

            name = nv.nvmlDeviceGetName(h).decode("utf-8", "ignore")
            mem  = nv.nvmlDeviceGetMemoryInfo(h)  # bytes
            util = nv.nvmlDeviceGetUtilizationRates(h).gpu
            temp = nv.nvmlDeviceGetTemperature(h, nv.NVML_TEMPERATURE_GPU)

            # اختیاری: بعضی کارت‌ها فن/توان ندارند
            try: fan = nv.nvmlDeviceGetFanSpeed(h)
            except: fan = None
            try: pwr = int(nv.nvmlDeviceGetPowerUsage(h) / 1000)  # mW → W
            except: pwr = None

            try: driver = nv.nvmlSystemGetDriverVersion().decode("utf-8", "ignore")
            except: driver = None

            nv.nvmlShutdown()
            return {
                "index": i,
                "name": name,
                "mem_mb": int(mem.total / (1024*1024)),
                "mem_used_mb": int(mem.used / (1024*1024)),
                "temp_c": int(temp) if temp is not None else None,
                "util_pct": int(util) if util is not None else None,
                "fan_pct": int(fan) if fan is not None else None,
                "power_w": int(pwr) if pwr is not None else None,
                "pstate": None,   # NVML اینجا مستقیم پشته را نمی‌دهد؛ nvidia-smi پوشش می‌دهد
                "driver": driver,
            }
        except Exception:
            try:
                nv.nvmlShutdown()
            except Exception:
                pass
            return None

#=========================================================================
# ------------------------- Timers & logs -------------------------
#==========================================================================
    def _tick_live(self):
        # فقط نمایش تایمرها و شمارنده‌ها را تازه کن
        try:
            self._refresh_counters_ui()
    
            # هر 10 ثانیه یک snapshot از progress ذخیره کن (نه بیشتر)
            now = time.time()
            last = float(getattr(self, "_last_progress_save", 0) or 0)
            if now - last >= 10:
                self._last_progress_save = now
                try:
                    self._save_progress()
                except Exception:
                    pass
        except Exception as ex:
            self._err(f"_tick_live: {ex}")
#==========================================================================
#   TICK SYS
#=========================================================================
    def _tick_sys(self):
        try:
            # CPU / RAM
            vm = psutil.virtual_memory()
            cpu_pct = psutil.cpu_percent()
            ram_used_gb  = vm.used  / (1024**3)
            ram_total_gb = vm.total / (1024**3)
            ram_pct = vm.percent

            # GPU index انتخاب‌شده از ComboBox
            pick_index = None
            try:
                if hasattr(self, "gpu_box"):
                    m = re.match(r'(\d+)', self.gpu_box.currentText() or "")
                    if m: pick_index = int(m.group(1))
            except Exception:
                pick_index = None

            # GPU info: NVML اولویت، بعد nvidia-smi
            info = self._gpu_query_from_nvml(pick_index) or self._gpu_query_from_nvidia_smi(pick_index)

            if info:
                used_mb  = info.get("mem_used_mb")
                total_mb = info.get("mem_mb")
                util_pct = info.get("util_pct")
                temp_c   = info.get("temp_c")
                fan_pct  = info.get("fan_pct")
                power_w  = info.get("power_w")
                name     = info.get("name") or "GPU"
                pstate   = info.get("pstate")
                driver   = info.get("driver")

                # VRAM string
                if total_mb:
                    if used_mb is not None:
                        vram_pct = int(100 * used_mb / total_mb) if total_mb > 0 else 0
                        vram_str = f"VRAM {used_mb/1024:.1f}/{total_mb/1024:.1f} GB ({vram_pct}%)"
                    else:
                        vram_str = f"VRAM {total_mb/1024:.1f} GB"
                else:
                    vram_str = "VRAM n/a"

                parts = [name]
                if util_pct is not None: parts.append(f"{util_pct}%")
                if temp_c   is not None: parts.append(f"{temp_c}°C")
                parts.append(vram_str)
                if fan_pct  is not None: parts.append(f"Fan {fan_pct}%")
                if power_w  is not None: parts.append(f"{power_w}W")
                if pstate: parts.append(pstate)
                if driver: parts.append(f"Driver {driver}")

                self.gpu_line = " | ".join(parts)
                if hasattr(self, "lbl_gpu_line"):
                    self.lbl_gpu_line.setText(f"🟢 GPU: {self.gpu_line}")
            else:
                if hasattr(self, "lbl_gpu_line"):
                    self.lbl_gpu_line.setText("🟢 GPU: —")

            # SYS line
            if hasattr(self, "lbl_sys"):
                self.lbl_sys.setText(f"🖥 CPU {cpu_pct:.0f}% | RAM {ram_used_gb:.1f}/{ram_total_gb:.1f} GB ({ram_pct:.0f}%)")
        except Exception:
            pass

# ========================================================================================
# ------------------------- Window close -------------------------
#=============================================================================================
    def closeEvent(self, e):
        
        try:
            # ⛔ در حال اسکن: اجازه‌ی بستن نده
            if getattr(self, "scanning", False):
                m = QMessageBox(self)
                m.setWindowTitle("خروج غیرمجاز")
                m.setIcon(QMessageBox.Icon.Warning)
                m.setText("اسکن در حال اجراست. تا زمانی که ⏹ Stop نزنید، برنامه بسته نمی‌شود.")
                btn_stop   = m.addButton("⏹ Stop", QMessageBox.ButtonRole.ActionRole)
                btn_cancel = m.addButton("ادامه‌ی اسکن", QMessageBox.ButtonRole.RejectRole)
                m.exec()
                # اگر کاربر خواست Stop شود، فقط استاپ را آغاز کن—ولی همچنان نبند
                if m.clickedButton() is btn_stop:
                    try:
                        self.stop_event.set()
                        # اگر هِلپر تِرِد-سیف داری از آن استفاده کن
                        if hasattr(self, "_ui_settext") and hasattr(self, "lbl_status"):
                            self._ui_settext(self.lbl_status, "🟡 STATUS: STOPPING")
                        elif hasattr(self, "lbl_status"):
                            self.lbl_status.setText("🟡 STATUS: STOPPING")
                    except Exception:
                        pass
                e.ignore()
                return
            # ✅ در حالت توقف، دیالوگ خروج عادی
            m = QMessageBox(self)
            m.setWindowTitle("Exit")
            m.setText("خروج از برنامه؟")
            yes    = m.addButton("YES (Save & Exit)", QMessageBox.ButtonRole.AcceptRole)
            no     = m.addButton("NO (Exit w/o Save)", QMessageBox.ButtonRole.RejectRole)
            cancel = m.addButton("Cancel", QMessageBox.ButtonRole.DestructiveRole)
            m.exec()
            if m.clickedButton() is yes:
                # در صورت نیاز تنظیمات را هم ذخیره کن
                try:
                    if getattr(self, "chk_save", None) and self.chk_save.isChecked():
                        self._save_settings()
                    self._save_progress()
                except Exception:
                    pass
                e.accept()
            elif m.clickedButton() is no:
                e.accept()
            else:
                e.ignore()
        except Exception:
            # در صورت هر خطا، برای جلوگیری از بسته شدن ناخواسته
            e.ignore()

#===================================================================================
#    # مسیر پوشهٔ ذخیرهٔ کلیدها (داخل پوشهٔ سشن فعلی)-----------   GET FOUND DIR
#=======================================================================================
    def get_found_dir(self):
        try:
            base = self.session_folder or self.base_dir
            fd = os.path.join(base, "found")
            os.makedirs(fd, exist_ok=True)
            return fd
        except Exception:
            # fallback
            fd = os.path.join(self.base_dir, "found")
            os.makedirs(fd, exist_ok=True)
            return fd

#==========================================================================
#       OPEN FOUND FOLDER
#==========================================================================
    def open_found_folder(self):
        from PyQt6.QtGui import QDesktopServices
        from PyQt6.QtCore import QUrl
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.get_found_dir()))
#==========================================================================
#       EXPORT FOUND TO CSV
#==========================================================================
    def export_found_to_csv(self, out_path: str | None = None):
        import csv, os, sqlite3
        try:
            # اگر از سیگنال clicked(bool) چیزی آمد، نادیده بگیر
            if isinstance(out_path, bool):
                out_path = None
    
            # مسیر پیش‌فرض داخل پوشه found/
            if out_path is None:
                default_name = os.path.join(self.get_found_dir(), "found_keys.csv")
                out_path, _ = QFileDialog.getSaveFileName(
                    self, "Save CSV", default_name, "CSV (*.csv)"
                )
                if not out_path:
                    return
    
            # --- خواندن رکوردها (سازگار با ts/timestamp/created_at)
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            cols = [r[1].lower() for r in c.execute("PRAGMA table_info(found_keys)")]
            if "ts" in cols and "timestamp" in cols:
                time_expr = "COALESCE(ts, timestamp, datetime('now')) AS ts"
            elif "ts" in cols:
                time_expr = "ts AS ts"
            elif "timestamp" in cols:
                time_expr = "timestamp AS ts"
            elif "created_at" in cols:
                time_expr = "created_at AS ts"
            else:
                time_expr = "datetime('now') AS ts"
    
            sql = f"""
                SELECT part_index, address, privkey, {time_expr}
                FROM found_keys
                ORDER BY id DESC
            """
            rows = c.execute(sql).fetchall()
            conn.close()
    
            if not rows:
                QMessageBox.information(self, "Export", "هیچ رکوردی برای خروجی نیست.")
                return
    
            # --- نوشتن CSV
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["part_index","address","privkey","timestamp"])
                for (p, a, k, t) in rows:
                    w.writerow([p, a, k, t])
    
            QMessageBox.information(self, "Export", f"CSV saved:\n{out_path}")
    
        except Exception as ex:
            self._err(f"export_found_to_csv: {ex}")
            QMessageBox.critical(self, "Export error", f"خطا در خروجی CSV:\n{ex}")

#=======================================================================================
#       OPEN DB FILE
#=======================================================================================
    def open_db_file(self):
        """progress.db را با برنامهٔ پیش‌فرض باز می‌کند؛
           اگر نشد، Snapshot می‌سازد؛ اگر باز هم نشد، در Explorer/Finder نشان می‌دهد."""
        try:
            if not getattr(self, "db_path", None) or not os.path.exists(self.db_path):
                QMessageBox.warning(self, "Database", "فایل دیتابیس پیدا نشد.")
                return

            path = os.path.abspath(self.db_path)

            def _open_with_default(p: str) -> bool:
                # تلاش 1: پلتفرم-ویژه
                try:
                    if sys.platform.startswith("win"):
                        try:
                            os.startfile(p)  # type: ignore[attr-defined]
                            return True
                        except Exception:
                            # تلاش 2: 'start' شلی
                            rc = subprocess.run(['cmd', '/c', 'start', '', p], shell=True).returncode
                            return (rc == 0)
                    elif sys.platform == "darwin":
                        return subprocess.run(["open", p], check=False).returncode == 0
                    else:
                        return subprocess.run(["xdg-open", p], check=False).returncode == 0
                except Exception:
                    # تلاش 3: QDesktopServices
                    try:
                        from PyQt6.QtGui import QDesktopServices
                        from PyQt6.QtCore import QUrl
                        return bool(QDesktopServices.openUrl(QUrl.fromLocalFile(p)))
                    except Exception:
                        return False

            # تلاش: بازکردن مستقیم خود فایل
            if _open_with_default(path):
                return

            # احتمالاً پسوند .db برنامهٔ پیش‌فرض ندارد یا Reader با WAL مشکل دارد → Snapshot
            try:
                snap_dir = self.get_found_dir()
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                snap_path = os.path.join(snap_dir, f"progress_snapshot_{ts}.db")
                shutil.copyfile(path, snap_path)
                if _open_with_default(snap_path):
                    QMessageBox.information(
                        self, "Database",
                        f"Viewer نتوانست DB زنده را باز کند؛ Snapshot باز شد:\n{snap_path}"
                    )
                    return
            except Exception as ex2:
                self._err(f"open_db_file snapshot: {ex2}")

            # آخرین راه: فایل را در فایل‌منیجر Highlight کن
            try:
                if sys.platform.startswith("win"):
                    subprocess.run(["explorer", "/select,", path], check=False)
                elif sys.platform == "darwin":
                    subprocess.run(["open", "-R", path], check=False)
                else:
                    from PyQt6.QtGui import QDesktopServices
                    from PyQt6.QtCore import QUrl
                    QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(path)))
            finally:
                QMessageBox.information(
                    self, "Database",
                    "به‌نظر می‌رسد هیچ برنامهٔ پیش‌فرضی برای .db ثبت نشده.\n"
                    "پیشنهاد: DB Browser for SQLite نصب و به .db Associate کن."
                )

        except Exception as ex:
            self._err(f"open_db_file: {ex}")
            QMessageBox.critical(self, "Database", f"خطا در بازکردن دیتابیس:\n{ex}")
#=======================================================================================
#  OPEN FOUND VIEWER
#===================================================================================
    def open_found_viewer(self):
        try:
            if not getattr(self, "db_path", None) or not os.path.exists(self.db_path):
                QMessageBox.warning(self, "Database", "فایل دیتابیس پیدا نشد.")
                return
            dlg = FoundViewerDialog(self.db_path, parent=self)
            dlg.exec()
        except Exception as ex:
            self._err(f"open_found_viewer: {ex}")

#==========================================================================
#       ITER FOUND JSONL
#==========================================================================
    def iter_found_jsonl(self):
        import glob, json
        for path in glob.glob(os.path.join(self.get_found_dir(), "found_keys*.jsonl")):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        yield json.loads(line)  # {"part_index":..,"address":..,"privkey":..,"ts":..}
#==========================================================================
#       SAVE FOUND KEY DB
#==========================================================================
    def save_found_key_db(self, part_idx: int, address: str, privkey: str):
        import sqlite3
        from datetime import datetime
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # تشخیص ستون زمان
        cols = [r[1].lower() for r in c.execute("PRAGMA table_info(found_keys)")]
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            if "timestamp" in cols:
                c.execute(
                    "INSERT INTO found_keys (part_index, address, privkey, timestamp) VALUES (?,?,?,?)",
                    (part_idx, address, privkey, now)
                )
            elif "ts" in cols:
                c.execute(
                    "INSERT INTO found_keys (part_index, address, privkey, ts) VALUES (?,?,?,?)",
                    (part_idx, address, privkey, now)
                )
            else:
                # اگر هیچ‌کدام نبود، ستون timestamp را اضافه کن
                c.execute("ALTER TABLE found_keys ADD COLUMN timestamp TEXT")
                c.execute(
                    "INSERT INTO found_keys (part_index, address, privkey, timestamp) VALUES (?,?,?,?)",
                    (part_idx, address, privkey, now)
                )
            conn.commit()
        finally:
            conn.close()

#==========================================================================
#           LAST SESSION FILE
#==========================================================================
    def _last_session_file(self): return os.path.join(self.base_dir, "LAST_SESSION_PATH.txt")
#==========================================================================
#   SAVE LAST SESSION PATH
#==========================================================================
    def _save_last_session_path(self):
        try:
            with open(self._last_session_file(), "w", encoding="utf-8") as f:
                f.write(self.session_folder or "")
        except Exception:
            pass
#==========================================================================
#       LOAD LAST SESSION PATH
#==========================================================================
    def _load_last_session_path(self) -> bool:
        try:
            p = self._last_session_file()
            if os.path.isfile(p):
                path = open(p, "r", encoding="utf-8").read().strip()
                if path and os.path.isdir(path):
                    self.session_folder = path
                    self.db_path = os.path.join(path, "progress.db")
                    return True
        except Exception:
            pass
        return False
    
# =======================================================================================================
#============== IS AUTO ENABLED ==========================================================================
    def _is_auto_enabled(self) -> bool:
        try:
            return bool( (hasattr(self,"chk_auto") and self.chk_auto.isChecked()) or
                         (hasattr(self,"btn_auto") and self.btn_auto.isChecked()) )
        except Exception:
            return False
#========================================================================================
#=================== INSTALL AUTO START HOOK =====================================================================
    def _install_auto_start_hook(self):
        """پس از بالا آمدن رویدادلوپ، اگر Auto روشن باشد و اسکن فعال نباشد، خودکار استارت کن."""
        QTimer.singleShot(1000, self._maybe_auto_start)
#========================================================================================
#==================MAY AUTO START======================================================================
    def _maybe_auto_start(self):
        try:
            if self._is_auto_enabled() and not getattr(self, "scanning", False):
                self.start_scan()   # یا start_scan_parts اگر اسم تابع تو همین است
        except Exception as e:
            self.log_error(f"AutoStart error: {e}")
#====================================================================================================
#       BACKUP DB
#====================================================================================================
    def _backup_db(self, extra_files=True, min_interval=10.0):
        """بکاپ امن sqlite + آینه‌سازی فایل‌های خروجی در ./backup (atomic و crash-safe)."""
        try:
            now = time.time()
            if (now - float(getattr(self, "_last_backup_ts", 0.0) or 0.0)) < float(min_interval or 0.0):
                return
            self._last_backup_ts = now

            if not getattr(self, "db_path", None):
                return
            sess_dir = os.path.dirname(self.db_path)
            backup_dir = os.path.join(sess_dir, "backup")
            os.makedirs(backup_dir, exist_ok=True)

            dst_db = os.path.join(backup_dir, "progress_backup.db")
            with sqlite3.connect(self.db_path) as src, sqlite3.connect(dst_db) as dst:
                src.backup(dst)  # اتمیک

            if extra_files:
                fd = os.path.join(sess_dir, "found")
                for name in ("found_keys.jsonl", "found_pairs.txt", "found_addresses.txt"):
                    srcf = os.path.join(fd, name)
                    if os.path.exists(srcf):
                        try:
                            shutil.copy2(srcf, os.path.join(backup_dir, name))
                        except Exception:
                            pass
        except Exception as e:
            self._err(f"DB backup failed: {e}")
#=============================================================================
    def _on_part_completed_ok(self, part_idx):
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path); c = conn.cursor()
            c.execute("UPDATE progress SET current_pos_hex=NULL WHERE id=1")
            conn.commit(); conn.close()
        except Exception as ex:
            self._err(f"clear current_pos_hex: {ex}")
        # ... done=1 و بقیه لاجیک خودت
#================================================================================
# ================= Helper: مدیریت و پاک‌سازی پروسه‌ها =================
    def _kill_process_tree(self, pid, timeout=5.0):
        """Terminate then kill process tree of pid. Returns True if process gone."""
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return True
        except Exception:
            return False

        try:
            children = p.children(recursive=True)
        except Exception:
            children = []

        # graceful terminate
        try:
            for ch in children:
                try: ch.terminate()
                except Exception: pass
            try: p.terminate()
            except Exception: pass
        except Exception:
            pass

        try:
            gone, alive = psutil.wait_procs([p] + children, timeout=timeout)
        except Exception:
            gone, alive = [], [p] + children

        if alive:
            # escalate to kill
            try:
                for a in alive:
                    try: a.kill()
                    except Exception: pass
            except Exception:
                pass
            try:
                psutil.wait_procs(alive, timeout=2.0)
            except Exception:
                pass

        return not psutil.pid_exists(pid)

    def _kill_leftover_DEMO(self, name_patterns=None):
        """Search and force-kill leftover DEMO processes before starting a new one."""
        if name_patterns is None:
            name_patterns = ["DEMO", "cub itcrack", "DEMO.exe", "DEMO.exe".lower()]
        try:
            for p in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    nm = (p.info.get('name') or "").lower()
                    cmd = " ".join(p.info.get('cmdline') or []).lower()
                    if any(pat.lower() in nm or pat.lower() in cmd for pat in name_patterns):
                        pid = int(p.info['pid'])
                        self._log(f"🛑 Killing leftover DEMO PID={pid} ({nm})")
                        self._kill_process_tree(pid, timeout=4.0)
                except Exception:
                    continue
        except Exception as ex:
            self._err(f"_kill_leftover_DEMO: {ex}")

    def _start_DEMO_proc(self, args, popen_kwargs=None):
        """Start DEMO after ensuring no leftovers; return proc object or None."""
        try:
            # kill leftovers first (conservative)
            try: self._kill_leftover_DEMO()
            except Exception: pass

            if popen_kwargs is None:
                popen_kwargs = {}

            # platform flags
            if os.name == 'nt':
                popen_kwargs.setdefault('creationflags', subprocess.CREATE_NEW_PROCESS_GROUP)
            else:
                popen_kwargs.setdefault('start_new_session', True)

            popen_kwargs.setdefault('cwd', self.base_dir)
            popen_kwargs.setdefault('stdout', subprocess.PIPE)
            popen_kwargs.setdefault('stderr', subprocess.STDOUT)
            popen_kwargs.setdefault('text', True)
            popen_kwargs.setdefault('bufsize', 1)

            proc = subprocess.Popen(args, **popen_kwargs)
            self.process = proc
            return proc
        except Exception as ex:
            self._err(f"_start_DEMO_proc failed: {ex}")
            return None

    def _ensure_proc_terminated(self, proc, wait_s=3.0):
        """Ensure a subprocess object/proc PID is terminated (best-effort)."""
        try:
            if not proc:
                return True
            pid = getattr(proc, "pid", None)
            if pid is None:
                # fallback: just try proc methods
                try:
                    if proc.poll() is None:
                        proc.terminate()
                        try: proc.wait(timeout=wait_s)
                        except Exception:
                            try: proc.kill()
                            except Exception: pass
                except Exception:
                    pass
                return True

            # if still alive, terminate
            try:
                if proc.poll() is None:
                    try: proc.terminate()
                    except Exception: pass
                    try: proc.wait(timeout=wait_s)
                    except Exception:
                        try: proc.kill()
                        except Exception: pass
            except Exception:
                pass

            # final OS-level check
            if psutil.pid_exists(pid):
                return self._kill_process_tree(pid, timeout=4.0)
            return True
        except Exception:
            return False

# ========================= → قرار بده داخل کلاس BitcrackGUI

    def _on_part_finished(self, finished_part_idx: int):
        """
        مدیریت پایان یک پارت: بروزرسانی counters، تصمیم‌گیری درباره پارت بعدی،
        مدیریت Random (دو حالت: with/without replacement) و مدیریت لوپ‌ها.
        فراخوانی شود هر بار که یک پارت کامل می‌شود.
        """
        try:
            # 1) افزایش شمارنده‌های Found/tested مرتبط (اگر لازم)
            # (اگر شما مقدارهایی مثل part_key_current را در جای دیگری آپدیت می‌کنید،
            #  اینجا فقط مرتب‌سازی و ذخیره progress انجام می‌شود.)

            # 2) علامت‌گذاری پارت تمام شده
            total_parts = int(getattr(self, "parts_spin").value()) if hasattr(self, "parts_spin") else 0

            # اگر از custom parts list استفاده می‌کنید، طول آن را بگیرید
            if hasattr(self, "_custom_parts_list") and self._custom_parts_list:
                total_parts = len(self._custom_parts_list)

            # update random-case counters
            if getattr(self, "_random_enabled", False):
                # حالت رندوم
                if not hasattr(self, "_remaining_parts_queue") or not self._remaining_parts_queue:
                    # build the queue depending on replacement policy
                    if getattr(self, "random_mode", "reproducible") == "fully":
                        # fully random - with replacement (we still may want to count runs)
                        # we will not maintain a queue; just increment _random_parts_done
                        pass
                    else:
                        # reproducible/random without replacement: build index queue
                        self._remaining_parts_queue = list(range(total_parts))
                        random.shuffle(self._remaining_parts_queue)

                # consume one entry (for without-replacement) or just count for with-replacement
                if getattr(self, "random_mode", "reproducible") != "fully":
                    if self._remaining_parts_queue:
                        try:
                            next_idx = self._remaining_parts_queue.pop(0)
                        except Exception:
                            next_idx = None
                    else:
                        next_idx = None
                else:
                    # fully random (with replacement): pick next random index
                    next_idx = random.randint(0, max(0, total_parts-1))

                # increase random parts done counter
                self._random_parts_done = int(getattr(self, "_random_parts_done", 0)) + 1

                # if queue exhausted (without replacement) OR we've run "total_parts" runs per loop:
                queue_empty = (getattr(self, "_remaining_parts_queue", None) is None) or (len(getattr(self, "_remaining_parts_queue", [])) == 0)
                if (self.random_mode == "reproducible" and queue_empty) or (self.random_mode == "fully" and self._random_parts_done >= total_parts):
                    # loop finished
                    self.loop_count = int(getattr(self, "loop_count", 0)) + 1
                    # reset random_parts_done for next loop
                    self._random_parts_done = 0
                    # rebuild for next loop if needed
                    self._remaining_parts_queue = None
                    # persist loop increment
                    try:
                        conn = sqlite3.connect(self.db_path); c = conn.cursor()
                        c.execute("UPDATE progress SET loop_count = ?, last_part = ? WHERE id = 1",
                                (self.loop_count, 0))
                        conn.commit(); conn.close()
                    except Exception:
                        pass

                    # check max_loops
                    max_loops = int(getattr(self, "max_loops", 0) or (self.max_loops_spin.value() if hasattr(self, "max_loops_spin") else 0))
                    if max_loops and self.loop_count >= max_loops:
                        # stop scanning
                        self._log("✅ Max loops reached — stopping scan.")
                        self.scanning = False
                        self.lbl_status.setText("🔴 STATUS: STOPPED")
                        return
                    else:
                        # start next loop: reset indices / counters and continue
                        self.current_part = 0
                        self.start_range_time = time.time()
                        self._log(f"🔁 Loop {self.loop_count} completed — starting next loop.")
                        # choose next part index according to random/seq policy
                        # For reproducible random, build new shuffled queue and pop first
                        if self.random_mode == "reproducible":
                            self._remaining_parts_queue = list(range(total_parts))
                            random.shuffle(self._remaining_parts_queue)
                            next_idx = self._remaining_parts_queue.pop(0) if self._remaining_parts_queue else 0
                        else:
                            # fully random: pick new random
                            next_idx = random.randint(0, max(0, total_parts-1))
                else:
                    # continue in the same loop: next_idx already computed
                    pass

                # set current_part appropriately (for UI)
                if next_idx is not None:
                    self.current_part = int(next_idx) + 1  # human readable (1..N)
                else:
                    self.current_part = int(getattr(self, "current_part", 0)) + 1

            else:
                # sequential mode
                self.current_part = int(getattr(self, "current_part", 0)) + 1
                if self.current_part > total_parts:
                    # finished a full loop
                    self.loop_count = int(getattr(self, "loop_count", 0)) + 1
                    # persist
                    try:
                        conn = sqlite3.connect(self.db_path); c = conn.cursor()
                        c.execute("UPDATE progress SET loop_count = ?, last_part = ? WHERE id = 1",
                                (self.loop_count, 0))
                        conn.commit(); conn.close()
                    except Exception:
                        pass

                    max_loops = int(getattr(self, "max_loops", 0) or (self.max_loops_spin.value() if hasattr(self, "max_loops_spin") else 0))
                    if max_loops and self.loop_count >= max_loops:
                        self._log("✅ Max loops reached — stopping scan.")
                        self.scanning = False
                        self.lbl_status.setText("🔴 STATUS: STOPPED")
                        return
                    else:
                        # start next loop
                        self._log(f"🔁 Loop {self.loop_count} completed — starting next loop.")
                        self.current_part = 1
                        self.start_range_time = time.time()

            # persist last_part
            try:
                conn = sqlite3.connect(self.db_path); c = conn.cursor()
                c.execute("UPDATE progress SET last_part = ?, loop_count = ?, updated_at = ? WHERE id = 1",
                        (int(self.current_part), int(getattr(self, "loop_count", 0)), datetime.now().isoformat()))
                conn.commit(); conn.close()
            except Exception:
                pass

            # update UI
            try:
                self._refresh_counters_ui()
            except Exception:
                pass

        except Exception as ex:
            self._err(f"_on_part_finished: {ex}")

#==========================================================================
#               RUN         RUN         RUN
#==========================================================================
if __name__ == "__main__":
    import sys
    # اگر از multiprocessing در ویندوز استفاده می‌کنید می‌توانید این خط را اضافه کنید:
    # from multiprocessing import freeze_support
    # freeze_support()

    # مطمئن شویم کلاس تعریف شده (در غیر این صورت خطای واضح‌تری بدهیم)
    try:
        BitcrackGUI  # فقط برای چک کردن وجود نام
    except NameError:
        raise RuntimeError("Class BitcrackGUI is not defined. Make sure the class definition appears before this block in the file.")

    # ایمن‌سازی ساخت QApplication (در صورت اجرای در محیط‌هایی که قبلاً آن را ساخته‌اند)
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)

    # ایجاد و نمایش پنجره اصلی
    win = BitcrackGUI()
    win.show()

    # Auto Start اگر هرکدام از سوییچ‌ها تیک داشت (استفاده از QTimer.singleShot برای تاخیر کوتاه)
    try:
        if (hasattr(win, "btn_auto") and getattr(win, "btn_auto").isChecked()) \
           or (hasattr(win, "chk_auto") and getattr(win, "chk_auto").isChecked()):
            QTimer.singleShot(1000, lambda: getattr(win, "start_scan", lambda: None)())
    except Exception as e:
        # لاگ خطا (به جای ساکت گذشتن) — اگر نمی‌خواهید چاپ شود، می‌توانید این خط را حذف کنید
        print(f"Auto-start check failed: {e}")

    # اجرای حلقهٔ اصلی برنامه
    try:
        sys.exit(app.exec())
    except Exception as e:
        # Handle platform-specific exec errors more gracefully if needed
        print(f"Application exec failed: {e}")
        raise