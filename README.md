# scanny-pyt

I made a small scanner application with Python 3.

It uses Scapy and Tkinter.

What it does :
- It scans for computers on the network (like the ping command)
- It detects open ports (like nmap)
- It captures network packets (like tcpdump)

In short : it's a simple network tool with a graphical window, that does somewhat the same thing as nmap, ping, and tcpdump.

## Installation

`git clone https://github.com/TLRKiliann/scanny-pyt.git`

`python3 -m venv scanny-pyt`

`source scanny-pyt/bin/activate`

`cd scanny-pyt`

`pip install scapy`

`pip freeze > requirements.txt`

## Run

`sudo python3 main.py`
