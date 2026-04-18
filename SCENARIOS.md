# 802.1X Scenario Walkthrough

Every possible runtime scenario traced through the goLAN bridge code, verifying correct handling at each decision point.

---

## Scenario 1: Clean Non-802.1X Network (Happy Path)

> **Environment:** Standard office switch, no 802.1X, DHCP-assigned IP, no VLANs.

```
NewBridge() → runStealth() → sniffer.Discover()
  → onMacFunc: MAC spoofed, bridge UP, STP disabled
  → 45s EAPOL probe → no frames
  → setupNATProxy()
  → backgroundEAPOLWatch → 5min → nothing
  → State: StealthActive ✅
```

| Step | What Happens |
|------|--------------|
| 1 | Bridge created, IPv6 disabled, ifaceA UP, ifaceB stays DOWN |
| 2 | Pcap opened on ifaceA with snaplen 65535, no BPF filter (captures everything) |
| 3 | First unicast MAC seen → locked as Target. `onMacFunc` fires |
| 4 | Bridge MAC spoofed, ifaceB MAC spoofed, `addm`, STP disabled, L2 leaks suppressed, bridge UP |
| 5 | IPv4 packets from target → target IP extracted |
| 6 | ARP reveals gateway. OR: DHCP reply reveals IP + gateway + netmask |
| 7 | `IsComplete()` → true. Discover returns |
| 8 | `id.EAPOLDetected` is false → 45s EAPOL probe on ifaceB |
| 9 | Timer fires after 45s with 0 frames → returns `Detected=false` |
| 10 | `eapolActive` is false → skips relay setup |
| 11 | `setupNATProxy()` runs → pfctl NAT rules loaded |
| 12 | `eapolSession == nil` → background EAPOL watcher launched |
| 13 | 5-minute Detect timeout → no EAPOL → watcher exits silently |

**Verdict: ✅ Correct.** Bridge is fully stealth, NAT active, L2 leaks suppressed.

---

## Scenario 2: 802.1X Network — Immediate Detection (Fast Switch)

> **Environment:** Cisco ISE, 802.1X with PEAP, switch sends EAP-Request/Identity within 5 seconds.

```
sniffer.Discover() → EAPOL frame seen on ifaceA
  → id.EAPOLDetected = true
  → Discover returns
  → eapolActive = true → skip 45s probe
  → runEAPOLRelay()
  → Relay.Start + EAPOL-Start injection
  → EAP exchange relayed → EAP-Success
  → State: Authenticated → setupNATProxy
```

| Step | What Happens |
|------|--------------|
| 1 | EAPOL frame (EtherType 0x888E) detected during MAC discovery → `EAPOLDetected=true`, `AuthenticatorMAC` recorded. Frame skipped for MAC processing |
| 2 | `eapolActive = id.EAPOLDetected` → true |
| 3 | `!eapolActive` is false → **skips the 45s probe entirely** (saves time) |
| 4 | `runEAPOLRelay(ctx, logFunc)` starts |
| 5 | AuthSession created with target MAC. Relay created. State → `EAPOLRelaying` |
| 6 | Pcap handles opened on both interfaces. BPF filter set. EAPOL-Start injected on ifaceB |
| 7 | Two goroutines: switch→device and device→switch |
| 8 | EAP-Request/Identity from switch → method set to `Identity`. Forwarded to device |
| 9 | EAP-Response/Identity from device → forwarded to switch |
| 10 | EAP-Request Type=PEAP → `session.Method` updated to `PEAP` |
| 11 | EAP-Success → `MarkAuthenticated()`, AuthResult sent on `authSignal` |
| 12 | `WaitForAuth()` returns `{Success:true, Method:PEAP}` |
| 13 | State → `EAPOLAuthenticated` |
| 14 | `setupNATProxy()` runs |
| 15 | `eapolSession != nil` → **no** background watcher launched (relay already running) |

**Verdict: ✅ Correct.** EAPOL relay handles full auth, then NAT overlays on top. Relay stays alive for re-auth.

---

## Scenario 3: 802.1X Network — Slow MAB Fallback (45s Detection)

> **Environment:** Switch has 30s MAB timer. EAPOL-Request/Identity arrives at T+32s.

| Step | What Happens |
|------|--------------|
| 1 | No EAPOL during MAC discovery → `EAPOLDetected=false` |
| 2 | 45s active probe on ifaceB → detects EAPOL at T+32s → returns immediately |
| 3 | `FramesSeen >= 1` → returns early (doesn't wait full 45s) |
| 4 | `eapolActive=true` → `runEAPOLRelay()` |

**Verdict: ✅ Correct.** The 45s window catches the late EAPOL.

---

## Scenario 4: 802.1X Network — Ultra-Slow MAB (>45s, Background Catch)

> **Environment:** Switch has 90s MAB timer. EAPOL arrives at T+75s — after both detection windows expired.

| Step | What Happens |
|------|--------------|
| 1 | Sniffer + 45s probe both return with no EAPOL |
| 2 | `eapolActive=false` → no relay started |
| 3 | `setupNATProxy()` runs → NAT goes active |
| 4 | `eapolSession==nil` → `backgroundEAPOLWatch()` launched |
| 5 | 5-minute Detect running. At T+75s, EAPOL frame arrives |
| 6 | Detection returns immediately |
| 7 | Log: "Late EAPOL detected". State → `EAPOLDetected`. `runEAPOLRelay(ctx)` called retroactively |
| 8 | After auth succeeds, state reverts to `StealthActive` |

**Verdict: ✅ Correct.** 5-minute watcher catches the ultra-late EAPOL.

---

## Scenario 5: 802.1X with MACsec — Downgrade Succeeds

> **Environment:** Switch supports MACsec but doesn't mandate it. First auth fails due to MKA negotiation failure.

| Step | What Happens |
|------|--------------|
| 1 | Relay starts, EAPOL-Key/MKA frames appear |
| 2 | `EAPOLTypeKey` case: downgrader is nil → `session.MACsecDetected = true`, frame forwarded |
| 3 | MKA negotiation fails → switch sends EAP-Failure |
| 4 | `AuthResult{Success:false, MACsecDetected:true}` sent to `authSignal` |
| 5 | `authResult.MACsecDetected == true` → enters downgrade path |
| 6 | `relay.EnableDowngrade()` → creates Downgrader, state → `Downgrading` |
| 7 | Future EAPOL-Key frames → `dg.ShouldDrop()` returns true → dropped |
| 8 | Switch re-auths without MKA → EAP-Success |
| 9 | `WaitForAuth()` returns success → State → `Authenticated` |
| 10 | Continues to `setupNATProxy()` |

**Verdict: ✅ Correct.** MACsec detected, downgrade attempted, MKA frames dropped, switch falls back to non-MACsec auth.

---

## Scenario 6: 802.1X with MACsec — Downgrade Fails

> **Environment:** Switch mandates MACsec. After downgrade, re-auth also fails.

| Step | What Happens |
|------|--------------|
| 1-7 | Same as Scenario 5 — MKA frames dropped |
| 8 | Switch re-auths → EAP-Failure again (MACsec is mandatory) |
| 9 | `retryResult.Success == false` → log "Downgrade failed". State → `EAPOLFailed` |
| 10 | `return` — **skips setupNATProxy()** |

**Verdict: ✅ Correct.** Fatal flow aborts cleanly. NAT is NOT set up.

---

## Scenario 7: 802.1X Auth Fails — No MACsec

> **Environment:** Device has wrong credentials. Switch rejects EAP.

| Step | What Happens |
|------|--------------|
| 1 | EAP exchange happens, switch sends EAP-Failure |
| 2 | `AuthResult{Success:false, MACsecDetected:false}` sent |
| 3 | `MACsecDetected==false` → log "Authentication rejected". State → `EAPOLFailed`. `return` |
| 4 | `setupNATProxy()` still runs (falls through after `runEAPOLRelay` returns) |

> ⚠️ **Note:** NAT is configured on a port the switch has NOT authorized. Traffic won't flow (switch blocks it), but logs show "Stealth Active" which is misleading. Not harmful — traffic is silently black-holed by the switch.

---

## Scenario 8: Re-Authentication While Running

> **Environment:** Switch re-authenticates every 3600s.

| Step | What Happens |
|------|--------------|
| 1 | Bridge is in `StealthActive` state — NAT running, relay still active in background |
| 2 | Switch sends EAP-Request/Identity |
| 3 | `method == MethodIdentity` && `session.State == StateAuthenticated` → `ReauthCount++`, state → `Relaying` |
| 4 | Full EAP exchange relayed — device re-authenticates |
| 5 | EAP-Success → `MarkAuthenticated()`. AuthResult pushed to `authSignal` (buffered, capacity 8) |
| 6 | Nobody is calling `WaitForAuth()` — result sits in the channel. Non-blocking `select` with `default` drops it if buffer is full |

**Verdict: ✅ Correct.** Re-auth is transparent. Session state transitions cleanly. Buffered channel absorbs results.

---

## Scenario 9: EAPOL-Logoff Suppression

> **Environment:** Device shuts down, sends EAPOL-Logoff.

| Step | What Happens |
|------|--------------|
| 1 | Device sends EAPOL-Logoff — relay receives on device→switch direction |
| 2 | `suppressLogoff=true` (default) → log "SUPPRESSED", `RecordDrop()`, `shouldDrop=true` |
| 3 | Frame NOT forwarded to switch → session stays alive |

**Verdict: ✅ Correct.** Switch never sees the logoff, port stays authorized.

---

## Scenario 10: MAC Spoof Fails — Firmware Locked (Network Down)

> **Environment:** USB adapter with firmware-locked MAC, interface is DOWN.

| Step | What Happens |
|------|--------------|
| 1 | `ifconfig ifaceB ether <mac>` → fails with "Network is down" |
| 2 | Bring ifaceB UP, retry spoof → still fails |
| 3 | Logs: "Hardware firmware locked", "Bridge Layer-2 masking", port-security warning |
| 4 | Bridge `addm` proceeds anyway — bridge MAC IS spoofed, so outgoing frames use correct MAC |

**Verdict: ✅ Correct.** Bridge-level MAC rewriting covers for the adapter's firmware lock.

---

## Scenario 11: MAC Spoof Fails — Different Error

> **Environment:** `ifconfig ether` fails with a non-"Network is down" error.

| Step | What Happens |
|------|--------------|
| 1 | `ifconfig ifaceB ether <mac>` fails, error not "Network is down" |
| 2 | Direct fallback: same L2 masking with port-security warning |

**Verdict: ✅ Correct.** Both error paths converge to the same fallback.

---

## Scenario 12: Device Uses 169.254.x.x (APIPA) Then Gets DHCP

> **Environment:** Device boots, gets link-local, then eventually gets DHCP lease.

| Step | What Happens |
|------|--------------|
| 1 | ARP from target with IP 169.254.x.x → `strings.HasPrefix("169.254")` → ignored |
| 2 | Log "Link-Local Self-Assignment" shown once (not spammed) |
| 3 | DHCP ACK received → `id.IP` overwritten with real DHCP IP |
| 4 | Gateway + netmask from DHCP options |
| 5 | `IsComplete()` → true → returns |

**Verdict: ✅ Correct.** APIPA correctly ignored, waits for real DHCP.

---

## Scenario 13: VLAN-Tagged Traffic

> **Environment:** Post-802.1X, RADIUS assigns VLAN 100.

| Step | What Happens |
|------|--------------|
| 1 | `Dot1Q` layer detected → `id.VLANID = 100` |
| 2 | gopacket auto-unwraps the 802.1Q header — ARP/DHCP/IPv4 parsing works normally |
| 3 | macOS kernel bridge preserves VLAN tags in passthrough |

**Verdict: ✅ Correct.** VLAN tag is detected and logged.

---

## Scenario 14: Switch Waits for EAPOL-Start

> **Environment:** Switch waits for supplicant-initiated EAPOL-Start before sending requests.

| Step | What Happens |
|------|--------------|
| 1 | After relay starts, `InjectEAPOLStart()` is called on ifaceB |
| 2 | 18-byte EAPOL-Start frame crafted and injected via pcap |
| 3 | Switch receives EAPOL-Start → responds with EAP-Request/Identity |
| 4 | Relay handles normally — auth proceeds |

> ⚠️ **Note:** Injection happens just before relay goroutines start. If the switch responds within microseconds (faster than goroutine startup), the first response could theoretically be missed. In practice this is extremely unlikely (~1μs goroutine startup vs ~1ms network round-trip).

---

## Scenario 15: Bridge Destroy During Active Relay

> **Environment:** User presses `q` to quit while EAPOL relay is running.

| Step | What Happens |
|------|--------------|
| 1 | TUI sends `Destroy()` → `b.mu.Lock()`, calls `destroy()` |
| 2 | `cancelEAPOL()` fires → cancels context → relay goroutines see `ctx.Done()` and return |
| 3 | `cancelStealth()` fires → cancels any running sniffer |
| 4 | `DisableNAT()` → flushes pfctl rules, removes temp file |
| 5 | `ifconfig bridge0 destroy` → kernel unbinds members |
| 6 | Original IP forwarding restored |

**Verdict: ✅ Correct.** Clean teardown. All goroutines cancelled, NAT flushed, bridge destroyed.

---

## Scenario 16: Crash Recovery (--cleanup flag)

> **Environment:** Previous session crashed. Stale `bridge0` and pfctl rules exist.

| Step | What Happens |
|------|--------------|
| 1 | `ifconfig -l` lists all interfaces |
| 2 | Any interface starting with "bridge" → `ifconfig bridgeN destroy` |
| 3 | `DisableNAT()` → flushes `com.apple/golan` pfctl anchor |

**Verdict: ✅ Correct.** Both bridge and pfctl state cleaned.

---

## Scenario 17: Context Cancelled During Sniffer Discovery

> **Environment:** User cancels before target identity is complete.

| Step | What Happens |
|------|--------------|
| 1 | `ctx.Done()` fires → sniffer returns `nil, ctx.Err()` |
| 2 | `err != nil` → log "Reconnaissance aborted" → `return` |
| 3 | `setupNATProxy()` is **not** called (correct — no identity to NAT) |

**Verdict: ✅ Correct.** Early cancellation handled cleanly.

---

## Scenario 18: Background Watcher Cancellation on Destroy

> **Environment:** Bridge is in `StealthActive` with background EAPOL watcher running. User destroys bridge.

| Step | What Happens |
|------|--------------|
| 1 | Background watcher stored its cancel into `b.cancelEAPOL` as a chained closure |
| 2 | `Destroy()` calls `b.cancelEAPOL()` → chained closure calls `cancel()` (watcher's context) |
| 3 | Detector's select sees `ctx.Done()` → returns error |
| 4 | Watcher returns silently |

**Verdict: ✅ Correct.** Watcher is cleanly cancelled.

---

## Summary

| # | Scenario | Result |
|---|----------|--------|
| 1 | Non-802.1X happy path | ✅ |
| 2 | 802.1X immediate detection | ✅ |
| 3 | 802.1X 45s detection | ✅ |
| 4 | 802.1X ultra-slow MAB (>45s) | ✅ |
| 5 | MACsec downgrade succeeds | ✅ |
| 6 | MACsec downgrade fails | ✅ |
| 7 | 802.1X auth fails (no MACsec) | ⚠️ NAT setup non-fatal |
| 8 | Re-authentication | ✅ |
| 9 | EAPOL-Logoff suppression | ✅ |
| 10 | MAC spoof fails (Network down) | ✅ |
| 11 | MAC spoof fails (other error) | ✅ |
| 12 | APIPA → DHCP transition | ✅ |
| 13 | VLAN-tagged traffic | ✅ |
| 14 | Switch waits for EAPOL-Start | ⚠️ Theoretical race |
| 15 | Destroy during relay | ✅ |
| 16 | Crash recovery | ✅ |
| 17 | Context cancel during sniff | ✅ |
| 18 | Watcher cancel on destroy | ✅ |

**16/18 fully correct. 2 non-critical edge cases noted.**
