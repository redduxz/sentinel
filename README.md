# sentinel

menu-bar network & persistence monitor for macOS. sits in the top bar, quietly watches
your machine and the network you're on, and flags when something looks off —
built for noticing weird stuff on public and untrusted networks.

all watchers run with **zero root, zero entitlements** — pure system-API polling.

## detections

| watcher | catches |
|---|---|
| wifi | evil twin (ssid seen on a different AP radio), open/unencrypted networks |
| arp | arp spoofing — gateway mac address flip |
| netconfig | dns resolver changes (hijack surface), gateway changes |
| portal | captive portal / inline content interception |
| connections | new outbound connection per process (lsof diff) |
| listeners | newly-bound listening services |
| devices | new devices joining the lan |
| persistence | new/modified LaunchAgents, LaunchDaemons, PrivilegedHelpers |

## layout

- `Sources/SentinelCore` — event model, parsers, watchers, `Monitor` engine (no UI deps)
- `Sources/SentinelApp` — SwiftUI `MenuBarExtra` widget: status card, detection feed, activity
- `Sources/sentinel-test` — assert-based checks (`XCTest` needs full Xcode; this runs on CLT)

## build / run

```bash
swift run sentinel        # runs the menu bar app (debug)
./scripts/bundle.sh       # builds dist/Sentinel.app
swift run sentinel-test   # parser checks
```

grant **location access** when prompted — macOS gates `ssid`/`bssid` behind it;
without it evil-twin detection degrades to network-change alerts.

## roadmap (needs privilege, so it's deliberately out of v1)

- packet-level detection (rogue dhcp, arp storms, port scans) — pcap/root helper
- Endpoint Security exec/file telemetry — needs Apple entitlement
- per-app flow blocking — NetworkExtension, approval path
