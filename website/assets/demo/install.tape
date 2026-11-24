# The installer demo of the README and the site. Run scripts/make_demo.py,
# which builds the card, serves the repository on loopback, starts VHS on
# this file from the repository root and encodes what it writes.

Output tmp/demo/recorded.mp4

Set Shell "bash"
Set FontFamily "DejaVu Sans Mono"
Set FontSize 15
Set LineHeight 1.15
Set Width 800
Set Height 460
Set Padding 16
Set Framerate 25
Set TypingSpeed 35ms
Set CursorBlink false
Set Theme { "name": "RetroBIOS", "background": "#12131c", "foreground": "#e6e6f0", "cursor": "#aebcff", "selection": "#3a3d52", "black": "#12131c", "red": "#ef9a9a", "green": "#a5d6a7", "yellow": "#ffcc80", "blue": "#90caf9", "magenta": "#aebcff", "cyan": "#aebcff", "white": "#cfd8dc", "brightBlack": "#7c82a3", "brightRed": "#ef9a9a", "brightGreen": "#a5d6a7", "brightYellow": "#ffcc80", "brightBlue": "#90caf9", "brightMagenta": "#c9d2ff", "brightCyan": "#c9d2ff", "brightWhite": "#e6e6f0" }

# The card mounted at /media/EASYROMS, an empty HOME, the prompt "$ ".
Hide
Type 'exec "$RETROBIOS_DEMO_SESSION"'
Enter
Wait+Screen@20s /\$/
Sleep 500ms
Show

Sleep 700ms
Type "curl -fsSL https://abdess.github.io/retrobios/i | sh -s -- --for-games"
Sleep 600ms
Screenshot tmp/demo/poster.png
Sleep 600ms
Enter

# The plan, opened on the one card found: only the files the games on it need.
Wait+Screen@60s /RetroBIOS: dArkOS or ArkOS \(RetroArch files\)/
Wait+Screen@60s /For the games on this card: yes/
Sleep 4500ms
Enter

# The summary.
Wait+Screen@60s /RetroBIOS: Done/
Sleep 4500ms
