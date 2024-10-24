There wasn't a SHA256 digest calculator based on RFC 7616, so I created one.
I wanted to parse values from Burp Suite to make using the Repeater easier.

You can convert this file into an executable using PyInstaller:

pyinstaller --onefile --windowed digestsha256calculator.py
