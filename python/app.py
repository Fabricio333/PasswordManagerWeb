"""Application entry point for the desktop password manager."""

from __future__ import annotations

import argparse
import logging

from gui import PasswordManagerGUI


def main(debug: bool = False) -> None:
    """Launch the Tkinter-based password manager.

    Parameters
    ----------
    debug:
        When ``True`` verbose logging is enabled across the application.
    """

    if debug:
        logging.basicConfig(level=logging.DEBUG)

    app = PasswordManagerGUI(debug=debug)
    app.mainloop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureVault Manager")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()
    main(debug=args.debug)
