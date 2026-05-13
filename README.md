<div align="center">
  
# ⚡ scanny-pyt

*Network scanning tool*

[![Stars](https://img.shields.io/github/stars/TLRKiliann/scanny-pyt?style=social)](https://github.com/TLRKiliann/scanny-pyt/stargazers)
[![Made with Python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/TLRKiliann/scanny-pyt)](https://github.com/TLRKiliann/scanny-pyt)

</div>

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
