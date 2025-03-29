import os

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            print(file)