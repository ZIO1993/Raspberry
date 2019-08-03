# WHO IS HOME

## Check which devices are connected to home wifi

### Installation
```bash
sudo apt-get install libpcap-dev arp-scan
sudo pip install scapy
sudo pip install telegram-send
```

Create or copy file `telegram-send.conf` to **WhoIsHome directiry** 

### Execution

```bash
sudo python WhoIsHome.py
```

## LOGS

```bash
sudo python WhoIsHome.py --logs
```

