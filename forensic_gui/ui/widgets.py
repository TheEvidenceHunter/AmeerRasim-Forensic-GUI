"""Small reusable widgets."""

from __future__ import annotations

import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QLineEdit, QVBoxLayout, QWidget


def label(text: str = "", role: str = "", wrap: bool = False) -> QLabel:
    lb = QLabel(text)
    if role:
        lb.setProperty("role", role)
    lb.setWordWrap(wrap)
    return lb


def card() -> QFrame:
    f = QFrame()
    f.setObjectName("card")
    return f


def mark(widget, **props):
    """Set dynamic style properties (primary/danger/chip...) and refresh the stylesheet."""
    for k, v in props.items():
        widget.setProperty(k, v)
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    return widget


class StatCard(QFrame):
    def __init__(self, title: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        self.title = label(title, "muted")
        self.value = label("0", "stat")
        self.sub = label("", "hint")
        for w in (self.title, self.value, self.sub):
            lay.addWidget(w)

    def set(self, value, sub: str = "", color: str = ""):
        self.value.setText(str(value))
        self.sub.setText(sub)
        self.value.setStyleSheet(f"color:{color};" if color else "")


class PathEdit(QLineEdit):
    """Line edit that accepts a dropped file."""

    fileDropped = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        for u in e.mimeData().urls():
            if u.isLocalFile() and os.path.isfile(u.toLocalFile()):
                self.setText(u.toLocalFile())
                self.fileDropped.emit(u.toLocalFile())
                e.acceptProposedAction()
                return


class DropFrame(QFrame):
    """Large drop target shown on the evidence page."""

    fileDropped = Signal(str)

    def __init__(self, text: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setAcceptDrops(True)
        self.setMinimumHeight(90)
        lay = QVBoxLayout(self)
        self.lbl = label(text, "muted")
        self.lbl.setAlignment(Qt.AlignCenter)
        lay.addWidget(self.lbl)

    def set_text(self, t: str):
        self.lbl.setText(t)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        for u in e.mimeData().urls():
            if u.isLocalFile() and os.path.isfile(u.toLocalFile()):
                self.fileDropped.emit(u.toLocalFile())
                e.acceptProposedAction()
                return


def h_row(*widgets, spacing: int = 8, stretch_last: bool = False) -> QWidget:
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(spacing)
    for x in widgets:
        lay.addWidget(x)
    if stretch_last:
        lay.addStretch(1)
    return w
