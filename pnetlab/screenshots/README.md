# Screenshot Evidence

This folder contains the **selected clean evidence images** used by the PNETLab documentation. Repeated, lower-quality, or redundant captures were intentionally excluded.

## Included

| File | Evidence |
|---|---|
| `topology.jpeg` | Final PNETLab NIDS topology |
| `ovs-mirror.png` | `ovs-vsctl show` and `ovs-vsctl list Mirror` verification |
| `ids-sniffer-running.png` | IDS sensor listening on `ens3` with live packet capture |
| `dashboard-overview.png` | Flask Alerts dashboard and attack distribution |
| `sniffer-bruteforce-portscan.png` | BruteForce and PortScan alert evidence |
| `sniffer-dos-three-sources.png` | DoS alerts from the three attack-source IPs; also documents the DDoS test remaining classified as DoS |
| `alerts-json.png` | Runtime `alerts.json` records for observed attack classes |
| `infiltration-alert.png` | Infiltration alert record |
| `server-network-services.png` | WEB-SRV01 interfaces and listening ports (`22`, `80`) |

## Placeholders / Not Retained as Clean Screenshots

The following tests are documented in `docs/TESTING.md`, but a clean final screenshot is not currently included:

- `benign-no-alert` — optional evidence showing normal client traffic with no new alert.
- `webattack-no-alert` — clean WebAttack generation/post-test evidence.
- `bot-no-alert` — clean Bot generation/post-test evidence.

These are intentionally left as placeholders rather than using duplicated or low-quality captures.
