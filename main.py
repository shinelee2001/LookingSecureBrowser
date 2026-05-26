import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from ui.main_window import MainWindow


def load_stylesheet(app: QApplication):
    qss_path = Path(__file__).parent / "ui" / "theme.qss"

    if qss_path.exists():
        app.setStyleSheet(qss_path.read_text(encoding="utf-8"))


def main():
    app = QApplication(sys.argv)

    load_stylesheet(app)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()