import pefile
import sys

file_path = sys.argv[1]

pe = pefile.PE(file_path)
print(pe.FileInfo)


