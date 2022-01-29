#!/usr/bin/python3

import os

print("Updating version")
stream = os.popen('git describe --tag --abbrev=0')
tagStr = stream.read()
ver = tagStr.strip().split(".")

with open("version.h") as inputFile:
    with open("temp", "w") as tempFile:
        for line in inputFile:
            if line.startswith("#define VER_MAJOR"):
                tempFile.write("#define VER_MAJOR " + ver[0] + "\n")
            elif line.startswith("#define VER_MINOR"):
                tempFile.write("#define VER_MINOR " + ver[1] + "\n")
            elif line.startswith("#define VER_PATCH"):
                tempFile.write("#define VER_PATCH " + ver[2] + "\n")
            else:
                tempFile.write(line)
        tempFile.close()
    inputFile.close()
os.rename("temp", "version.h")
