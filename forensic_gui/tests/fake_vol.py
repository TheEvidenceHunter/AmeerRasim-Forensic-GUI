#!/usr/bin/env python3
"""Stand-in vol.py: emits real-shaped JSON + progress so the whole GUI pipeline can be tested."""
import sys, json, time
a = sys.argv[1:]
plugin = next(x for x in a if "." in x and not x.startswith("-") and not x.startswith("/"))
sys.stderr.write("\rProgress:  10.00\t\tScanning\r"); sys.stderr.flush(); time.sleep(0.15)
sys.stderr.write("\rProgress:  80.00\t\tScanning\r"); sys.stderr.flush()
if "fail" in plugin:
    sys.stderr.write("A symbol table requirement was not fulfilled\n"); sys.exit(1)
D = {
 "windows.pslist": [{"PID":4,"PPID":0,"ImageFileName":"System","ExitTime":None,"__children":[]},
   {"PID":700,"PPID":4,"ImageFileName":"svch0st.exe","ExitTime":None,"__children":[]},
   {"PID":800,"PPID":4,"ImageFileName":"WINWORD.EXE","ExitTime":None,"__children":[]},
   {"PID":801,"PPID":800,"ImageFileName":"powershell.exe","ExitTime":None,"__children":[]}],
 "windows.cmdline": [{"PID":801,"Process":"powershell.exe","Args":"powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA","__children":[]}],
 "windows.info": [{"Variable":"Is64Bit","Value":"True","__children":[]}],
}
out = D.get(plugin, [{"Note": "x", "__children": []}])
print(); print(json.dumps(out, indent=2))
