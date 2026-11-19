"""Manual kd.exe attach launcher (fallback when the kd-mcp bridge cannot bind).

Usage:
    python kd_launch.py                     # defaults to the WORKING config
    python kd_launch.py [port] [key]        # override after an approved retarget

The kd process is spawned detached with real file handles (kd_manual.log /
kd_err.log next to this script's project base), so its output survives the
parent's exit and avoids the PowerShell-relay "Could not write to pipe, 1450"
death. Do not run UDP listeners on the debug port while this kd holds it.
"""
import subprocess, time, os, sys

KD = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe"
BASE = r"C:\Users\User\Desktop\DiffingBaseDir"
SYMBOLS = "srv*" + BASE + r"\symbols*https://msdl.microsoft.com/download/symbols"

# Working config (hostip:192.168.2.100 on the bridged KDNET switch) — change
# only if the user repins/retargets KDNET and tells you the new values.
DEFAULT_PORT = "50035"
DEFAULT_KEY = "39z62jesay7u1.3f6sxmnlawu4a.3088uwh3cz7w7.233wo7v16odgi"

port = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PORT
key = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_KEY
args = ["-k", "net:port=" + port + ",key=" + key, "-y", SYMBOLS]

for f in ("kd_manual.log", "kd_err.log", "kd_pid.txt"):
    p = os.path.join(BASE, f)
    try: os.remove(p)
    except OSError: pass

p = subprocess.Popen(
    [KD] + args,
    stdout=open(os.path.join(BASE, "kd_manual.log"), "wb"),
    stderr=open(os.path.join(BASE, "kd_err.log"), "wb"),
    cwd=BASE,
    creationflags=0x08000000,  # CREATE_NO_WINDOW
)
with open(os.path.join(BASE, "kd_pid.txt"), "w") as f:
    f.write(str(p.pid))

time.sleep(4)
print("kd launched, pid =", p.pid)
