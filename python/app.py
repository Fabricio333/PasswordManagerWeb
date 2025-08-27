from gui import PasswordManagerGUI


def main() -> None:
    """Launch the Tkinter-based password manager."""
    app = PasswordManagerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
