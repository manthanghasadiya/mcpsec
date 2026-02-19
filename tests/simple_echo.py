import sys
import os

if sys.platform == "win32":
    import msvcrt
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

stdin = sys.stdin.buffer
stdout = sys.stdout.buffer

while True:
    line = stdin.readline()
    if not line:
        break
    stdout.write(b"Echo: " + line)
    stdout.flush()
