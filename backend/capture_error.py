import sys

try:
    with open("backend.log", "r", encoding="utf-16", errors="replace") as f:
        lines = f.readlines()
        content = "".join(lines[-300:])

    with open("error.txt", "w", encoding="utf-8") as f_out:
        f_out.write(content)

    print(f"Captured {len(lines)} lines (tail 300) to error.txt")

except Exception as e:
    print(f"Error reading log: {e}")
