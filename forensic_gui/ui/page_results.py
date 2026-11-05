"""Results page: one sortable/filterable table per plugin, global IOC search, exports."""

from __future__ import annotations

from typing import Dict, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QGuiApplication
from PySide6.QtWidgets import (QAbstractItemView, QFileDialog, QHBoxLayout, QHeaderView, QInputDialog, QLineEdit,
                               QMenu, QMessageBox, QPushButton, QTableView, QTabWidget, QTreeWidget, QTreeWidgetItem,
                               QDialog, QVBoxLayout, QWidget)

from ..core.results import ResultTable, fmt
from ..i18n import tr
from .models import ResultProxy, ResultTableModel
from .widgets import label


class ResultView(QWidget):
    """Table + filter box for a single plugin."""

    def __init__(self, plugin: str, table: ResultTable, parent=None):
        super().__init__(parent)
        self.plugin = plugin
        self.model = ResultTableModel(table, self)
        self.proxy = ResultProxy(self)
        self.proxy.setSourceModel(self.model)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        top = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setLayoutDirection(Qt.LeftToRight)
        self.filter.setClearButtonEnabled(True)
        self.filter.setPlaceholderText(tr("results.filter") + "   pid:4 name:svchost")
        self.filter.textChanged.connect(self._filter)
        self.count = label("", "hint")
        top.addWidget(self.filter, 1)
        top.addWidget(self.count)
        lay.addLayout(top)
        self.view = QTableView()
        self.view.setModel(self.proxy)
        self.view.setSortingEnabled(not table.tree)  # sorting would destroy the tree order
        self.view.setAlternatingRowColors(True)
        self.view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.view.setWordWrap(False)
        self.view.verticalHeader().setVisible(False)
        self.view.verticalHeader().setDefaultSectionSize(24)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self._menu)
        self.view.setStyleSheet("font-family: Consolas, 'DejaVu Sans Mono', monospace; font-size: 12px;")
        lay.addWidget(self.view, 1)
        self.proxy.layoutChanged.connect(self._update_count)
        self.proxy.modelReset.connect(self._update_count)
        self.proxy.rowsInserted.connect(self._update_count)
        self._size_columns()
        self._update_count()

    def _size_columns(self):
        self.view.resizeColumnsToContents()
        h = self.view.horizontalHeader()
        for i in range(self.model.columnCount()):
            h.resizeSection(i, min(max(h.sectionSize(i), 60), 360))

    def _filter(self, text: str):
        self.proxy.set_filter_text(text)
        self._update_count()

    def _update_count(self, *_):
        total = len(self.model.table)
        shown = self.proxy.rowCount()
        self.count.setText(tr("results.shown", shown=shown, total=total) if shown != total
                           else f"{total} {tr('results.rows')}")

    def _menu(self, pos):
        idx = self.view.indexAt(pos)
        if not idx.isValid():
            return
        src = self.proxy.mapToSource(idx)
        m = QMenu(self)
        a1 = m.addAction(tr("results.copy_cell"))
        a2 = m.addAction(tr("results.copy_row"))
        a3 = m.addAction(tr("results.filter_value"))
        act = m.exec(self.view.viewport().mapToGlobal(pos))
        text = self.model.display(src.row(), src.column()).strip()
        if act == a1:
            QGuiApplication.clipboard().setText(text)
        elif act == a2:
            QGuiApplication.clipboard().setText(
                "\t".join(fmt(self.model.table.rows[src.row()].get(c)) for c in self.model.columns))
        elif act == a3:
            col = self.model.columns[src.column()]
            self.filter.setText(f'{col.replace(" ", "")}:"{text}"')

    def scroll_to_source_row(self, row: int):
        idx = self.proxy.mapFromSource(self.model.index(row, 0))
        if not idx.isValid():  # hidden by the filter -> clear it
            self.filter.clear()
            idx = self.proxy.mapFromSource(self.model.index(row, 0))
        self.view.selectRow(idx.row())
        self.view.scrollTo(idx, QAbstractItemView.PositionAtCenter)


class ResultsPage(QWidget):
    def __init__(self, state, parent=None):
        super().__init__(parent)
        self.state = state
        self.views: Dict[str, ResultView] = {}
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        top = QHBoxLayout()
        self.title = label("", "title")
        self.btn_search = QPushButton()
        self.btn_csv, self.btn_json = QPushButton(), QPushButton()
        self.btn_search.clicked.connect(self.search_all)
        self.btn_csv.clicked.connect(lambda: self.export("csv"))
        self.btn_json.clicked.connect(lambda: self.export("json"))
        top.addWidget(self.title)
        top.addStretch(1)
        for b in (self.btn_search, self.btn_csv, self.btn_json):
            top.addWidget(b)
        lay.addLayout(top)
        self.empty = label("", "muted")
        self.empty.setAlignment(Qt.AlignCenter)
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.tabs.tabCloseRequested.connect(self._close_tab)
        lay.addWidget(self.empty, 1)
        lay.addWidget(self.tabs, 1)
        state.resultsChanged.connect(self._results_changed)
        state.findingsChanged.connect(self._apply_flags)
        self.retranslate()
        self._sync_empty()

    def retranslate(self):
        self.title.setText(tr("results.title"))
        self.btn_search.setText(tr("results.search_all"))
        self.btn_csv.setText("CSV")
        self.btn_json.setText("JSON")
        self.empty.setText(tr("results.empty"))
        for v in self.views.values():
            v.filter.setPlaceholderText(tr("results.filter") + "   pid:4 name:svchost")

    # ------------------------------------------------------------ tabs
    def _sync_empty(self):
        has = self.tabs.count() > 0
        self.empty.setVisible(not has)
        self.tabs.setVisible(has)
        for b in (self.btn_search, self.btn_csv, self.btn_json):
            b.setEnabled(has)

    def _short(self, plugin: str) -> str:
        parts = plugin.split(".")
        return ".".join(parts[:-1]) if len(parts) > 2 and parts[-1][:1].isupper() else plugin

    def _results_changed(self, plugin: str):
        if not plugin:  # case reset
            self.tabs.clear()
            self.views.clear()
            self._sync_empty()
            return
        table = self.state.results.get(plugin)
        if table is None:
            return
        old = self.views.pop(plugin, None)
        if old:
            idx = self.tabs.indexOf(old)
            self.tabs.removeTab(idx)
            old.deleteLater()
        v = ResultView(plugin, table)
        v.model.set_flags(self.state.flagged.get(plugin, {}))
        self.views[plugin] = v
        self.tabs.addTab(v, f"{self._short(plugin)}  ({len(table)})")
        self.tabs.setCurrentWidget(v)
        self._sync_empty()

    def _close_tab(self, i: int):
        w = self.tabs.widget(i)
        for k, v in list(self.views.items()):
            if v is w:
                del self.views[k]
        self.tabs.removeTab(i)
        w.deleteLater()
        self._sync_empty()

    def _apply_flags(self):
        for plugin, v in self.views.items():
            v.model.set_flags(self.state.flagged.get(plugin, {}))

    def goto(self, plugin: str, row: Optional[int]):
        v = self.views.get(plugin)
        if not v:
            return
        self.tabs.setCurrentWidget(v)
        if row is not None:
            v.scroll_to_source_row(row)

    # ------------------------------------------------------------ export
    def current(self) -> Optional[ResultView]:
        w = self.tabs.currentWidget()
        return w if isinstance(w, ResultView) else None

    def export(self, kind: str):
        v = self.current()
        if not v:
            QMessageBox.information(self, tr("msg.info"), tr("msg.no_results"))
            return
        base = self.state.case.exports_dir if self.state.case.folder else ""
        name = f"{v.plugin.replace('.', '_')}.{kind}"
        path, _ = QFileDialog.getSaveFileName(self, tr("btn.save"), str(base / name) if base else name,
                                              "CSV (*.csv)" if kind == "csv" else "JSON (*.json)")
        if not path:
            return
        t = v.model.table
        try:
            with open(path, "w", encoding="utf-8-sig" if kind == "csv" else "utf-8", newline="") as f:
                f.write(t.to_csv() if kind == "csv" else t.to_json())
        except OSError as e:
            QMessageBox.warning(self, tr("msg.error"), str(e))
            return
        self.state.audit(f"Exported {v.plugin} to {path}")
        self.state.log("ok", tr("msg.exported", path=path))

    # ------------------------------------------------------------ global search
    def search_all(self):
        if not self.state.results:
            return
        text, ok = QInputDialog.getText(self, tr("results.search_all"), tr("results.search_prompt"))
        if not ok or not text.strip():
            return
        dlg = QDialog(self)
        dlg.setWindowTitle(tr("results.search_all"))
        dlg.resize(820, 460)
        lay = QVBoxLayout(dlg)
        tree = QTreeWidget()
        tree.setColumnCount(3)
        tree.setHeaderLabels([tr("results.col_plugin"), tr("results.col_row"), tr("results.col_match")])
        tree.setRootIsDecorated(False)
        tree.setAlternatingRowColors(True)
        total = 0
        for plugin, t in self.state.results.items():
            for r in t.find(text, limit=300):
                total += 1
                hit = next((f"{c}={fmt(t.rows[r].get(c))}" for c in t.columns
                            if text.lower() in fmt(t.rows[r].get(c)).lower()), "")
                it = QTreeWidgetItem([plugin, str(r + 1), hit[:300]])
                it.setData(0, Qt.UserRole, (plugin, r))
                tree.addTopLevelItem(it)
        tree.resizeColumnToContents(0)
        lay.addWidget(label(tr("results.hits", n=total) if total else tr("results.nomatch"), "h2"))
        lay.addWidget(tree, 1)

        def jump(item, _col=0):
            plugin, row = item.data(0, Qt.UserRole)
            dlg.accept()
            self.goto(plugin, row)

        tree.itemDoubleClicked.connect(jump)
        dlg.exec()
