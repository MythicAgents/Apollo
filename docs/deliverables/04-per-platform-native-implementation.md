# Deliverable 4: Per-Platform Native Implementation

## Scope Statement

This document defines platform-native controls for macOS, Windows, Linux, iOS, and Android, including anti-tampering, screenshot protection realities, clipboard isolation, installer/update mechanics, native messaging constraints, and platform threat models.

## 1. Cross-Platform Design Principles

1. Enforce policy as close to OS primitives as possible.
2. Keep browser UX behavior consistent while documenting platform limitations.
3. Prefer signed and attestable execution paths over opaque anti-debug tricks.
4. Expose control capability matrix to admins (supported/limited/unsupported by OS).

## 2. Platform Capability Matrix

| Capability | macOS | Windows | Linux | iOS | Android |
|---|---|---|---|---|---|
| Screenshot deterrence | strong | strong | limited on Wayland | medium | strong |
| Clipboard isolation | strong | strong | medium | medium | strong |
| Device attestation | medium | strong | medium | strong | strong |
| Anti-tamper depth | medium-high | high | medium | medium | medium-high |
| Auto-update flexibility | high | high | high | app-store constrained | app-store constrained |

## 3. macOS Implementation

### Build + Signing
- Universal binary (`arm64`, `x86_64`) via Xcode and GN.
- Developer ID signing, hardened runtime, notarization, stapled tickets.

### Anti-Tampering
- Endpoint Security framework for process events and tamper telemetry.
- Entitlements: minimal `com.apple.security.cs.*` profile; no unsupported private entitlements.
- LaunchDaemon for posture helper and LaunchAgent for user session helper.

### Screenshot Blocking (macOS reality)
- Use `NSWindow.sharingType = .none` for sensitive windows.
- Detect screen capture authorization state using `CGPreflightScreenCaptureAccess`.
- On capture start, blur sensitive surfaces and suspend content rendering.
- No kernel-level interception of `kCGDisplayStream...`; not technically viable.

### Clipboard Isolation
- Enforce per-origin clipboard read/write policy in browser process.
- Use temporary per-profile clipboard vault with TTL (default 60s) for sensitive context.

## 4. Windows Implementation

### Anti-Tampering
- WDAC policy package for signed execution allowlist.
- VBS/HVCI compatibility required; optional PPL usage for helper service where feasible.
- AMSI integration for script/event scans in helper context.

### Screenshot Blocking
- `SetWindowDisplayAffinity(hWnd, WDA_EXCLUDEFROMCAPTURE)` on Win10 2004+.
- Fallback `WDA_MONITOR` where unsupported.
- DWM edge cases logged; policy can degrade to watermark-only mode.

### Clipboard Isolation
- Intercept clipboard actions via browser hooks + optional native helper monitoring.
- Block copy from restricted pages; sanitize paste into restricted contexts.

## 5. Linux Implementation

### Anti-Tampering
- seccomp-bpf profiles for helper binaries.
- AppArmor or SELinux profiles depending on distro.
- IMA/EVM optional for integrity-sensitive deployments.

### Screenshot Blocking
- X11: partial deterrence via window hints and overlay modes.
- Wayland: compositor-governed; full prevention generally not possible.
- Admin UI must show "deterrence only" status on unsupported compositor paths.

### Clipboard Isolation
- X11 selection/clipboard policy wrapper where available.
- Wayland clipboard control varies by compositor; enforce browser-local policy and redact operations.

## 6. iOS Implementation

### Anti-Tampering + Attestation
- DeviceCheck + App Attest bound to tenant enrollment.
- MDM payload ingestion for managed app restrictions.

### Screenshot/Recording Response
- Observe `UIScreen.capturedDidChangeNotification`.
- Apply secure blur overlay and pause sensitive rendering.

### Clipboard
- Gate paste actions via managed-app policy checks.

## 7. Android Implementation

### Anti-Tampering + Attestation
- Play Integrity API verdict bound to session token claims.
- Managed configuration for Android Enterprise Work Profile.

### Screenshot Blocking
- `FLAG_SECURE` for sensitive Activities/Windows.
- Detect MediaProjection attempts where possible and trigger policy action.

### Clipboard
- Work profile clipboard restrictions + browser-level restrictions for sensitive origins.

## 8. Native Messaging Host Specification

| Item | Requirement |
|---|---|
| Transport | stdin/stdout JSON-RPC over OS-managed host registration |
| Auth | mutual process identity checks + signed host binary |
| Policy | host capabilities scoped by tenant policy |
| Logging | structured events only, no raw sensitive content |

## 9. Packaging and Update

| Platform | Installer | Update Strategy |
|---|---|---|
| macOS | signed `.pkg` with pre/post scripts | Sparkle + Sentinel channel control |
| Windows | WiX `.msi` + optional bootstrapper | Omaha protocol-compatible updater |
| Linux | `.deb` / `.rpm` / AppImage / Flatpak | package repo + Omaha-like channel |
| iOS | `.ipa` App Store + MDM private distribution | App Store managed updates |
| Android | `.aab` Play + enterprise options | Play managed rollout |

## 10. Threat Model by Platform (Sample 5 each)

| Platform | Threat | Mitigation |
|---|---|---|
| macOS | TCC abuse to bypass capture detection | TCC state checks + user prompts + policy fallback |
| macOS | helper binary replacement | notarization + signature verification at startup |
| Windows | DLL injection into browser process | code integrity + exploit mitigation policies |
| Windows | screenshot API fallback bypass | capability validation + watermark fallback |
| Linux | Wayland compositor capture bypass | transparent admin warnings + watermark + RBI redirect |
| Linux | helper privilege escalation | seccomp + least-privileged service accounts |
| iOS | jailbroken device bypass | attestation fail => restricted policy mode |
| iOS | managed config tampering | MDM signature checks + periodic sync |
| Android | rooted device bypass | Play Integrity strict verdict requirement |
| Android | overlay attack during prompts | secure flags + foreground checks |

## 11. Build-vs-Buy-vs-Integrate Notes

| Capability | Decision |
|---|---|
| Desktop anti-tamper helpers | Build core, integrate OS-native trust primitives |
| Mobile attestation | Integrate first-party APIs (App Attest, Play Integrity) |
| Installer tooling | Use mature tooling (WiX, Sparkle, package managers) rather than bespoke |

## 12. Performance Budgets

| Budget Item | Target |
|---|---|
| Native helper CPU overhead | `<2%` average on enterprise laptop baseline |
| Clipboard decision latency | `<10ms` p95 local decision path |
| Screenshot policy response | `<100ms` from capture-state event to overlay action |

## 13. Failure Modes

| Failure | Detection | Recovery |
|---|---|---|
| Attestation API outage | posture service health checks | fail-safe restricted mode |
| Update signature mismatch | updater verify logs | hold rollout + rollback channel |
| Native host crash loop | crash counter + watchdog | disable host feature and alert admin |

## 14. Assumptions & Open Questions

### Assumptions
1. Managed deployment is preferred for enterprise environments.
2. Wayland limitations are acceptable if transparently disclosed and policy-compensated.

### Open Questions
1. Is kernel-level driver support on Windows in scope for v1 or post-GA hardening?
2. Which Linux distros are contractual support targets at beta?

**Deliverable 4 of 15 complete. Ready for Deliverable 5 — proceed?**
