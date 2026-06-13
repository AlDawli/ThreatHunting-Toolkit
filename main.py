#!/usr/bin/env python3
"""
main.py — Threat Hunting Toolkit Entry Point
─────────────────────────────────────────────
Usage
-----
  python main.py            # Interactive prompt
  python main.py --web      # Flask web server  → http://localhost:5000
  python main.py --desktop  # Tkinter desktop GUI
"""
import argparse
import sys
from pathlib import Path

# ── Ensure project root is on the path ────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent))


BANNER = r"""
  ╔══════════════════════════════════════════════════╗
  ║                                                  ║
  ║     ⬡  THREAT HUNTING TOOLKIT  v1.0  ⬡          ║
  ║        IOC · Hash · Domain · URL · PDF           ║
  ║                                                  ║
  ╚══════════════════════════════════════════════════╝
"""


def _prompt_interface() -> str:
    print(BANNER)
    print("  [1]  Web Interface    (Flask → http://localhost:5000)")
    print("  [2]  Desktop GUI      (Tkinter)")
    print("  [0]  Exit\n")
    return input("  Select interface: ").strip()


def launch_web() -> None:
    from config.settings import FLASK_PORT, FLASK_DEBUG, VIRUSTOTAL_API_KEY
    if not VIRUSTOTAL_API_KEY:
        print("\n  ⚠  WARNING: VT_API_KEY not set in .env — analysis features will be disabled.")
        print("     See .env.example for instructions.\n")
    print(f"\n  🌐  Starting web interface → http://localhost:{FLASK_PORT}")
    print("      Press Ctrl+C to stop.\n")
    from interfaces.web.app import create_app
    app = create_app()
    app.run(host="127.0.0.1", port=FLASK_PORT, debug=FLASK_DEBUG)


def launch_desktop() -> None:
    from config.settings import VIRUSTOTAL_API_KEY
    if not VIRUSTOTAL_API_KEY:
        print("\n  ⚠  WARNING: VT_API_KEY not set in .env — analysis features will be disabled.\n")
    print("  🖥   Starting desktop GUI…\n")
    from interfaces.desktop.app import DesktopApp
    DesktopApp().run()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Threat Hunting Toolkit — multi-interface IOC analysis platform")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--web",     action="store_true", help="Launch Flask web interface")
    group.add_argument("--desktop", action="store_true", help="Launch Tkinter desktop GUI")
    args = parser.parse_args()

    if args.web:
        launch_web()
    elif args.desktop:
        launch_desktop()
    else:
        choice = _prompt_interface()
        if choice == "1":
            launch_web()
        elif choice == "2":
            launch_desktop()
        elif choice == "0":
            print("\n  Goodbye.\n")
            sys.exit(0)
        else:
            print("\n  Invalid choice. Run again and enter 1, 2, or 0.\n")
            sys.exit(1)


if __name__ == "__main__":
    main()
