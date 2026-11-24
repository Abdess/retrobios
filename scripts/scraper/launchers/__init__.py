"""The launcher layer of each platform: what its launch code looks for, under
which name and in which folder, and what it hands to the core or emulator,
read from that code at the revision the platform file pins.

One module per platform reads its launchers (batocera.py, retrobat.py...).
configgen.py holds the record every reader returns and the errors a reader
raises when the code no longer has the shape it reads. shell.py and
csharp_source.py read the shell and C# sources several platforms share.
"""
