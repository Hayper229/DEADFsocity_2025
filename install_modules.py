#!/bin/python3
import os
p = "[OK]"
pr = "[NO]"

a=os.system("pip install requests")
if a == 0:print(f"{p} Requests installed!")

else:print(f"{pr} Requests not installed!!")

a=os.system("pip install requests")
if a == 0:print(f"{p} Requests installed!")

else:print(f"{pr} Requests not installed!!")

print(a)
# 0 = OK
# if number != 0  NOT INSTALLED
