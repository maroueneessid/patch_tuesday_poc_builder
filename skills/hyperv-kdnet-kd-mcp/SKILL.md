---
name: hyperv-kdnet-kd-mcp
description: Mandatory setup and usage guide for kernel-debugging a Hyper-V VM from the same host over KDNET using the kd-mcp tools (originsec/kd-mcp). Covers manual one-time VM/network/bcdedit setup that must be done interactively BEFORE any kd-mcp attach, elevation requirements, zombie kd handling, and the hard rule to never retarget KDNet to a different port unprompted. Use whenever the user wants to set up, validate, or re-establish kernel debugging against Win11Poc (or any Hyper-V target) with kd/windbg/kd-mcp.
---

# Hyper-V Kernel Debug from Same Host (KDNET + kd-mcp)

> **Machine-specific record:** the IPs / ports / keys / VM name below are this
> workstation's validated Win11Poc configuration (as of 2026-11-19). On other machines,
> follow the setup steps to discover your own values — the workflow is identical.

Setup for kernel-debugging a Hyper-V guest from the host itself. The manual part
below is best done interactively by the user (or with the user supervising) BEFORE
touching the kd-mcp tools. If any of these prerequisites are missing, the MCP attach
will spin on `Context server request timeout` and produce zombie kd processes —
do not brute-force the attach; fix the environment instead.

Reference tool: https://github.com/originsec/kd-mcp

## 1. Create the VM with Secure Boot disabled

KDNET debugging requires Secure Boot off on the target VM.

## 2. Define an external virtual switch and attach it to the VM

In Hyper-V Manager (_Virtual Switch Manager → New virtual switch_):

- **Connection type** → `External`
- **Allow management operating system to share this network adapter** → **Enabled**
- **VLAN ID** → Disabled

The shared-management-OS option is what exposes the LAN IP on the host-side
`vEthernet (KDNET)` adapter — kd.exe binds there (see §3).

## 3. Match IP ranges (host KDNET adapter ↔ VM)

The host vNIC `vEthernet (KDNET)` and the VM's NIC on that switch must share one
subnet (e.g. host `192.168.2.100`, VM `192.168.2.101`). Static-configure the VM
if the LAN's DHCP is slow to answer it.

**Why hostip must be that exact address:** on this host, ANY wildcard (0.0.0.0)
UDP bind silently rebinds onto the default/bridged NIC address. `kd.exe`/debuggers
bind `0.0.0.0:port`, so they effectively listen on the bridged NIC IP only. The
guest hello must therefore target **the address of `vEthernet (KDNET)`**. A hello
sent to any other interface's IP (vSwitch NAT, other adapters) never reaches kd.

## 4. Enable kernel debug (elevated prompt, on the VM)

```bat
bcdedit /debug on
:: reboot
bcdedit /dbgsettings net hostip:192.168.2.100 port:50035 newkey
```

- `newkey` generates and prints a 4-part base36 key — save it, it is needed for
  every debugger connect (`net:port=<port>,key=<key>`).
- Guest needs a reboot after any `bcdedit /dbgsettings` change.

## 5. KDNET only — no serial/COM fallback

Gen 2 VMs have no legacy UART. Do NOT attempt `hyperv_configure_kdcom`/COM-pipe
debugging on a Gen 2 target: it silently emits nothing and can hang the guest's
boot (`debugtype Serial` once stalled a boot past 5 minutes; recovery restored it).
KDNET over the external switch is the only supported transport here.

## Rule 6. NEVER retarget KDNet to a new port unprompted. IT WORKS, DO NOT TOUCH.

The guest's `bcdedit /dbgsettings` (hostip/port/key) is a validated, working
configuration. Do not change the port, re-generate the key, or re-run kdnet
config utilities on your own initiative. If an attach fails, suspect the HOST side
(stale kd process holding the port, kd-mcp stuck) — not the guest parameters.

## Working config on this machine (validated + checkpointed `kdbg-verified`)

- VM: `Win11Poc` (Gen 2, Secure Boot off), external switch `KDNET`, bridged NIC IP `192.168.2.100`
- Guest debug NIC IP: `192.168.2.101`
- Connection string for every kd/windbg/kd-mcp attach:
  `net:port=50035,key=39z62jesay7u1.3f6sxmnlawu4a.3088uwh3cz7w7.233wo7v16odgi`
  (port + key from the user's `bcdedit /dbgsettings ... newkey` output — do not
  regenerate; ask the user if these ever look unfamiliar)

## Usage through the kd MCP tools

- The agent needs **elevation** for all Hyper-V MCP management tools AND for kd/
  debugger control. When Hyper-V calls start failing with *"You do not have the
  required permission"* or the shell loses admin, tell the user to restore
  elevation — do not attempt workarounds.
- **Attach once and keep the session.** Every `kernel_attach` spawns its own kd.exe.
  A bridge request that exits with `Context server request timeout` can leave its
  kd process running; it may keep holding the port after a later kill.
- **If a new kd needs to spawn but port 50035 is taken:** find the holder with
  `scripts/kd_status.ps1` (shows every kd PID, its parent, command line and the
  sockets it binds), force-kill it (`taskkill /F /PID <pid>` in an elevated
  prompt — non-admin kills can report "killed" while the process lingers),
  **restart the kd-mcp server if its state is stuck**, then re-attach via
  `kernel_attach` with the exact port/key above. If kd processes keep
  reappearing or won't die, check kd_pid.txt / parent chain with kd_status.ps1
  before assuming it is yours.
- Do not run diagnostic UDP listeners on the debug port while kd is attached:
  a socket bound to the specific address steals delivery from kd's wildcard bind.
- If `kernel_attach` connects, the kernel halts at `nt!DbgBreakPointWithStatus`
  (int 3) — that IS the successful state. Validate, then `raw "g"` to resume.

## Validation checklist (before any checkpoint)

With the bridge attached:

1. `status` → `connected: true`
2. `get_regs` → full x64 register file, RIP at `nt!DbgBreakPointWithStatus`
3. `stack_trace` → break-in frame chain present
4. `raw "lm"` → `nt` resolves with PDB symbols (ntkrnlmp.pdb)
5. `raw "g"` (or `go`) to resume — empty timeout response = running normally

Only after all of that pass: create a checkpoint (e.g. `kdbg-verified`). Never
checkpoint while the kernel is halted at the break-in — resume first.

## Supporting scripts (in this skill's `scripts/` dir)

- `scripts/kd_launch.py` — fallback **manual kd attach** when the MCP bridge
  cannot bind (e.g. port contention or a stuck bridge). Spawns kd.exe detached
  with real file handles so output survives the parent's exit (avoids the
  PowerShell relay "Could not write to pipe, 1450" death). Logs land in the
  project base as `kd_manual.log`; PID in `kd_pid.txt`. Defaults to the working
  config; accepts `python kd_launch.py [port] [key]` after an approved change.
  Do not run UDP listeners on the debug port while kd holds it — a
  specifically-bound socket steals delivery from kd's wildcard bind.
- `scripts/kd_status.ps1` — list kd.exe processes (PID, parent, command line,
  UDP binds) plus holders of the debug port. Pre-flight check before any attach.
- `scripts/kd_pid.txt`, `kd_manual.log`, `kd_err.log` in the project base are
  transient outputs of kd_launch.py — safe to delete when no kd is running.
