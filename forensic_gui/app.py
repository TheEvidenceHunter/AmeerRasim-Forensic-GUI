"""Application entry point."""

from __future__ import annotations

import sys


def main(argv=None) -> int:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication

    from . import APP_NAME, ORG_NAME
    from .i18n import is_rtl, set_language
    from .ui.main_window import MainWindow
    from .ui.state import AppState

    argv = list(sys.argv if argv is None else argv)
    app = QApplication(argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(ORG_NAME)
    app.setStyle("Fusion")

    state = AppState()
    set_language(state.pref("lang", "en"))
    app.setLayoutDirection(Qt.RightToLeft if is_rtl() else Qt.LeftToRight)

    win = MainWindow(state)
    win.show()
    for arg in argv[1:]:  # forensic-studio path/to/image.raw
        if not arg.startswith("-"):
            win.p_case._set_image(arg)
            win.go(1)
            break
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
