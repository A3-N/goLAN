# todo
- send command 
- secrets add eap/eapol 

| EAP Method               | Hashcat Mode  |
| ------------------------ | ------------- |
| EAP-MD5                  | 4800          |
| Cisco LEAP               | 5500          |
| MSCHAPv2 (PEAP-MSCHAPv2) | 5500          |

# golan

Command-first macOS inline bridge tool for staging two physical adapters,
capturing host-side traffic, and running a transparent Layer 2 bridge.

## Run

```bash
sudo go run ./cmd/golan
```

Root privileges are required because adapter inspection, interface setup,
bridging, and packet capture need privileged access.

## Storage

Runtime files are stored under the invoking user's home config folder, even
when the tool is run with `sudo`:

```text
~/.config/goLAN/configs/
~/.config/goLAN/pcaps/<timestamp>/
```

On capture stop or quit, pcap directories are finalized so the non-root sudo
user owns them and directories/files are readable by all. Saved JSON configs are
written under the same config root and finalized the same way.

Local `config.json` and `pcaps/` paths are ignored if they exist in the working
tree.

## Current Scope

- Discover local network adapters.
- Select one host adapter and one switch adapter.
- Isolate selected adapters with `set <adapter> <host|switch>`.
- Enter adapter context with `conf <adapter>` and then use `up`, `down`, or
  `set <property> <value>`.
- Passively capture host-side traffic with `start listen`.
- Start a transparent kernel bridge with `start bridge`.
- Capture listen and bridge pcaps under `~/.config/goLAN/pcaps`.
- Save and load staged adapter configs as JSON under `~/.config/goLAN/configs`.
- Keep `start listen` and `start bridge` mutually exclusive.
- Use the host MAC, either discovered from host-side listen/bridge sniffing or
  set manually, as the bridge identity.
- Pass normal Ethernet traffic through the kernel bridge and relay EAPOL frames
  in userspace for 802.1X passthrough.

## Commands

```text
help
show adapters
show config
show bridge
set <adapter> <host|switch>
set adapter <adapter> [host|switch]
conf <adapter>
unset
unset adapter <adapter>
set ip <value|auto>
set mac <value|auto>
set state <up|down|auto>
up
down
load
load <name>
start listen
stop listen
start bridge
stop bridge
refresh
clear
quit
```

Press `ctrl+s` to prompt for a filename and save the current staged config.
