import os
import re
import subprocess as sp

pwd = sp.getoutput("pwd")

file_path = os.path.join(pwd, "tinyxml2", "outputs", "tinyxml2.txt")

reg_exp_1 = "tinyxml2\..{1,3}:\d{1,10}:\d{1,10},\s{1}col:\d{1,10}>"
reg_exp_2 = "tinyxml2\..{1,3}:\d{1,10}:\d{1,10}\s<Spelling=line:\d{1,10}:\d{1,10}>,\sline:\d{1,10}:\d{1,10}>"
with open(file_path, "r") as file:
    cnt = 0
    for line in file:
        if re.search(reg_exp_1, line):
            cnt += 1
            data = line.split(":")[-3:]
            row = data[0]
            col_start = data[1].split(",")[0]
            col_end = data[-1].split(">")[0]
            print({"row": row, "col": {"start": col_start, "end": col_end}})
            continue

        if re.search(reg_exp_2, line):
            cnt += 1
            data = line.split(":")[2:]
            row = data[0]
            col_start = data[1].split(" ")[0]
            col_end = data[-1].split(">")[0]
            print({"row": row, "col": {"start": col_start, "end": col_end}})
    print(cnt)


data = "- c:@F@sscanf@</Users/attilagyen/Documents/phd/python/tinyxml2/tinyxml2.cpp:692:13 <Spelling=line:100:25>, line:692:41>".split(
    ":"
)[
    2:
]

row = data[0]
col_start = data[1].split(" ")[0]
col_end = data[-1].split(">")[0]
print(row, col_start, col_end)
