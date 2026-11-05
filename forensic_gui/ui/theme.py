"""Dark / light themes as a generated Qt stylesheet."""

from __future__ import annotations

from typing import Dict

PALETTES: Dict[str, Dict[str, str]] = {
    "dark": dict(
        bg="#0e141d", surface="#141c28", surface2="#1a2433", border="#263449", text="#e7edf5", muted="#8b9bb0",
        accent="#3b9cff", accent_hover="#5eaeff", accent_text="#06121f", select="#1d3a5e", row_alt="#111926",
        ok="#34c98a", warn="#f2a93b", danger="#ff5c6c", input="#0f1722", scroll="#2a3a52",
    ),
    "light": dict(
        bg="#f3f6fa", surface="#ffffff", surface2="#edf2f8", border="#d4dce8", text="#17222e", muted="#5d6d80",
        accent="#0b6fd0", accent_hover="#2a85e0", accent_text="#ffffff", select="#cfe3fb", row_alt="#f8fafd",
        ok="#1f9d63", warn="#b97800", danger="#d6293b", input="#ffffff", scroll="#c3cedd",
    ),
}

SEVERITY_COLORS = {
    "critical": "#e5173f", "high": "#f06a1d", "medium": "#e0a400", "low": "#2fa05a", "info": "#6b7a8d",
}

MONO = "Consolas, 'Cascadia Mono', 'DejaVu Sans Mono', Menlo, monospace"


def sev_color(sev: str) -> str:
    return SEVERITY_COLORS.get(sev, "#6b7a8d")


def build_qss(name: str, rtl: bool = False) -> str:
    p = PALETTES.get(name, PALETTES["dark"])
    end = "left" if rtl else "right"      # QSS has no logical (inline-end) properties
    start = "right" if rtl else "left"
    return f"""
* {{ outline: 0; }}
QWidget {{ background: {p['bg']}; color: {p['text']}; font-size: 13px; }}
QMainWindow, QDialog {{ background: {p['bg']}; }}
QLabel {{ background: transparent; }}
QLabel[role="title"] {{ font-size: 22px; font-weight: 700; }}
QLabel[role="h2"] {{ font-size: 15px; font-weight: 600; }}
QLabel[role="muted"] {{ color: {p['muted']}; }}
QLabel[role="hint"] {{ color: {p['muted']}; font-size: 12px; }}
QToolTip {{ background: {p['surface2']}; color: {p['text']}; border: 1px solid {p['border']}; padding: 5px; }}

/* sidebar */
#sidebar {{ background: {p['surface']}; border-{end}: 1px solid {p['border']}; }}
#sidebar QLabel {{ background: transparent; }}
#brand {{ font-size: 17px; font-weight: 800; color: {p['accent']}; }}
#nav {{ background: transparent; border: none; padding: 4px 8px; }}
#nav::item {{ padding: 10px 12px; margin: 2px 0; border-radius: 8px; color: {p['muted']}; }}
#nav::item:hover {{ background: {p['surface2']}; color: {p['text']}; }}
#nav::item:selected {{ background: {p['select']}; color: {p['text']}; font-weight: 600; }}

/* cards & groups */
#card, QGroupBox {{ background: {p['surface']}; border: 1px solid {p['border']}; border-radius: 10px; }}
#card QLabel, QGroupBox QLabel {{ background: transparent; }}
QGroupBox {{ margin-top: 16px; padding: 14px 12px 12px 12px; font-weight: 600; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 14px; padding: 0 6px; color: {p['muted']}; background: {p['bg']}; }}
QLabel[role="stat"] {{ font-size: 30px; font-weight: 700; }}

/* inputs */
QLineEdit, QPlainTextEdit, QTextEdit, QTextBrowser, QComboBox, QSpinBox {{
  background: {p['input']}; border: 1px solid {p['border']}; border-radius: 7px; padding: 6px 9px;
  selection-background-color: {p['accent']}; selection-color: {p['accent_text']}; }}
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QTextEdit:focus {{ border: 1px solid {p['accent']}; }}
QLineEdit[readOnly="true"] {{ color: {p['muted']}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{ background: {p['surface']}; border: 1px solid {p['border']};
  selection-background-color: {p['select']}; color: {p['text']}; }}
QCheckBox {{ spacing: 8px; background: transparent; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 4px; border: 1px solid {p['border']}; background: {p['input']}; }}
QCheckBox::indicator:checked {{ background: {p['accent']}; border: 1px solid {p['accent']}; }}

/* buttons */
QPushButton, QToolButton {{ background: {p['surface2']}; border: 1px solid {p['border']}; border-radius: 7px;
  padding: 7px 14px; }}
QPushButton:hover, QToolButton:hover {{ border-color: {p['accent']}; background: {p['select']}; }}
QPushButton:disabled, QToolButton:disabled {{ color: {p['muted']}; background: {p['surface']}; border-color: {p['border']}; }}
QPushButton[primary="true"] {{ background: {p['accent']}; color: {p['accent_text']}; border: 1px solid {p['accent']}; font-weight: 600; }}
QPushButton[primary="true"]:hover {{ background: {p['accent_hover']}; }}
QPushButton[primary="true"]:disabled {{ background: {p['border']}; color: {p['muted']}; border-color: {p['border']}; }}
QPushButton[danger="true"] {{ color: {p['danger']}; }}
QPushButton[preset="true"] {{ text-align: {start}; padding: 10px 14px; background: {p['surface']}; }}
QPushButton[chip="true"] {{ border-radius: 13px; padding: 4px 12px; }}
QPushButton[chip="true"]:checked {{ background: {p['select']}; border-color: {p['accent']}; }}
QToolButton::menu-indicator {{ image: none; }}

/* tables / trees / lists */
QTableView, QTreeWidget, QTableWidget, QListWidget {{ background: {p['surface']}; alternate-background-color: {p['row_alt']};
  border: 1px solid {p['border']}; border-radius: 8px; gridline-color: transparent;
  selection-background-color: {p['select']}; selection-color: {p['text']}; }}
QTableView::item, QTreeWidget::item, QTableWidget::item {{ padding: 3px 6px; }}
QHeaderView {{ background: transparent; }}
QHeaderView::section {{ background: {p['surface2']}; color: {p['muted']}; border: none;
  border-bottom: 1px solid {p['border']}; border-{end}: 1px solid {p['border']}; padding: 6px 8px; font-weight: 600; }}
QTableCornerButton::section {{ background: {p['surface2']}; border: none; }}

/* tabs */
QTabWidget::pane {{ border: 1px solid {p['border']}; border-radius: 8px; top: -1px; background: {p['surface']}; }}
QTabBar::tab {{ background: transparent; color: {p['muted']}; padding: 8px 14px; border-bottom: 2px solid transparent; }}
QTabBar::tab:selected {{ color: {p['text']}; border-bottom: 2px solid {p['accent']}; }}
QTabBar::tab:hover {{ color: {p['text']}; }}

/* progress */
QProgressBar {{ background: {p['surface2']}; border: none; border-radius: 4px; height: 8px; text-align: center; color: transparent; }}
QProgressBar::chunk {{ background: {p['accent']}; border-radius: 4px; }}

/* scrollbars */
QScrollBar:vertical {{ background: transparent; width: 12px; margin: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 12px; margin: 0; }}
QScrollBar::handle {{ background: {p['scroll']}; border-radius: 5px; min-height: 28px; min-width: 28px; }}
QScrollBar::handle:hover {{ background: {p['accent']}; }}
QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{ background: none; border: none; width: 0; height: 0; }}

/* menus / status */
QMenuBar {{ background: {p['surface']}; border-bottom: 1px solid {p['border']}; }}
QMenuBar::item {{ padding: 6px 12px; background: transparent; }}
QMenuBar::item:selected {{ background: {p['select']}; border-radius: 6px; }}
QMenu {{ background: {p['surface']}; border: 1px solid {p['border']}; padding: 6px; }}
QMenu::item {{ padding: 6px 22px; border-radius: 6px; }}
QMenu::item:selected {{ background: {p['select']}; }}
QMenu::separator {{ height: 1px; background: {p['border']}; margin: 6px 4px; }}
QStatusBar {{ background: {p['surface']}; border-top: 1px solid {p['border']}; }}
QStatusBar QLabel {{ color: {p['muted']}; }}
QSplitter::handle {{ background: {p['border']}; }}
QMessageBox {{ background: {p['bg']}; }}
"""
