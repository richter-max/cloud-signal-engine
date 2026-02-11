with open("backend.log", encoding="utf-16", errors="ignore") as f:
    lines = f.readlines()
    # Print last 200 lines to be safe
    for line in lines[-200:]:
        print(line.rstrip())
