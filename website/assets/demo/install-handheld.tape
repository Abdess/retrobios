# The installer demo of the "On the device" tab: the full-screen interface
# on dArkOS, at the 640x480 screen of an RG351MP, as the Tools menu launcher
# starts it. Run scripts/make_demo.py --variant handheld, which builds the
# card and dArkOS's root, serves the repository on loopback, starts VHS on
# this file from the repository root and encodes what it writes. Enter is
# what gptokeyb sends for A (ports/shared/retrobios.gptk).

Output tmp/demo/recorded-handheld.mp4

Set Shell "bash"
Set FontFamily "DejaVu Sans Mono"
Set FontSize 16
Set LineHeight 1.15
Set Width 640
Set Height 480
Set Padding 8
Set Framerate 25
Set TypingSpeed 35ms
Set CursorBlink false
Set Theme { "name": "RetroBIOS", "background": "#12131c", "foreground": "#e6e6f0", "cursor": "#aebcff", "selection": "#3a3d52", "black": "#12131c", "red": "#ef9a9a", "green": "#a5d6a7", "yellow": "#ffcc80", "blue": "#90caf9", "magenta": "#aebcff", "cyan": "#aebcff", "white": "#cfd8dc", "brightBlack": "#7c82a3", "brightRed": "#ef9a9a", "brightGreen": "#a5d6a7", "brightYellow": "#ffcc80", "brightBlue": "#90caf9", "brightMagenta": "#c9d2ff", "brightCyan": "#c9d2ff", "brightWhite": "#e6e6f0" }

# dArkOS's root, the card at /roms, the interface started.
Hide
Type 'exec "$RETROBIOS_DEMO_SESSION"'
Enter
Wait+Screen@60s /A Install/
Sleep 300ms
Show

# The plan, opened on the system found: only the files the games on the
# card need.
Sleep 300ms
Screenshot tmp/demo/poster-handheld.png
Sleep 4500ms
Enter

# A: install. The progress, then the summary.
Wait+Screen@60s /RetroBIOS: Done/
Sleep 4500ms
