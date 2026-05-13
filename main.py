#!/usr/bin/env python3

import subprocess
import platform
import sys
import tkinter as tk
from tkinter import messagebox, simpledialog
from scapy.all import *

txt_intro = """
  ██████ ▄████▄   ▄▄▄       ███▄    █  ███▄    █  ▓██   ██▓   ██▓███   ▓██   ██▓ ▄▄▄█████▓
▒██    ▒▒██▀ ▀█  ▒████▄     ██ ▀█   █  ██ ▀█   █   ▒██  ██▒  ▓██░  ██▒ ▒██  ██▒ ▓  ██▒ ▓▒
░ ▓██▄  ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒▓██  ▀█ ██▒   ▒██ ██░  ▓██░ ██▓▒  ▒██ ██░ ▒ ▓██░ ▒░
  ▒   ██▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒▓██▒  ▐▌██▒   ░ ▐██▓░  ▒██▄█▓▒ ▒  ░ ▐██▓░ ░ ▓██▓ ░ 
▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░▒██░   ▓██░   ░ ██▒▓░  ▒██▒ ░  ░  ░ ██▒▓░   ▒██▒ ░ 
▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░   ▒ ▒     ██▒▒▒   ▒▓▒░ ░  ░   ██▒▒▒    ▒ ░░   
░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░░ ░░   ░ ▒░  ▓██ ░▒░   ░▒ ░      ▓██ ░▒░      ░    
░  ░  ░  ░          ░   ▒      ░   ░ ░    ░   ░ ░   ▒ ▒ ░░    ░░        ▒ ▒ ░░     ░      
      ░  ░ ░            ░  ░         ░          ░   ░ ░                  ░ ░              
"""
width = 90
txt_cmd = "sudo python3 main.py"
txt_target = "- target => scanme.nmap.org: 45.33.32.156 -"
print(txt_intro)
print(txt_cmd.center(width))
print()
print(txt_target.center(width))
print()

def scanner():
    root = tk.Tk()
    root.withdraw()
    
    messagebox.showinfo("Info", "Welcome dans Scanny-Pyt")
    
    continuer = messagebox.askyesno("Continuer", "Voulez-vous continer ?")
    
    while continuer == True:

        scan_choice = messagebox.askyesno("Scan choice", "Voulez-vous choisir un scan ?")

        if scan_choice == True:
        
            choice_cmd = simpledialog.askinteger("Choix du scan", "Quel scan choisissez-vous ? : \n1.nmap \n2.scapy \n3.tcpdump", minvalue=1, maxvalue=3)

            if choice_cmd == 1:
                print("Scan avec nmap: nmap -sS -p 22, 80, 443, 3306, 8080 <addr_ip>")
                messagebox.showinfo("Info", "Scan avec nmap : nmap -sS -p 22, 80, 443, 3306, 8080 <addr_ip>")

                system = platform.system()

                if system in ["Linux", "Darwin"]:
                    print("Interfaces disponibles :")
                    for iface_name, iface_obj in conf.ifaces.items():
                        print(f"  - {iface_name}: {iface_obj.ip}")
                    
                else:
                    print("Couldn't works with your system...")
                    sys.exit(1)

                interface_input = simpledialog.askstring("Nom de l'interface internet", "Entrer par exemple: en1, eth0,...")

                if interface_input is None:
                    print("Saisie annulée...")
                    sys.exit(1)

                interface_input_lower_strip = interface_input.lower().strip()

                if interface_input_lower_strip:
                    print("Vous avez entrer : ", interface_input_lower_strip)
                else:
                    print("Pas la bonne interface...")
                    sys.exit(1)

                iface = interface_input_lower_strip

                try:
                    ip = get_if_addr(iface)
                    print(f"✅ IP de l'interface : {ip}")

                except:
                    print(f"❌ Interface {iface} non trouvée")
                    sys.exit(1)

                ports = [22, 80, 443, 3306, 8080]

                ports_ouverts = []

                for port in ports:
                    pkt = IP(dst=ip)/TCP(dport=port, flags="S")
                    reponse = sr1(pkt, timeout=3, verbose=False)
                    
                    if reponse is None:
                        print(f"⏰ Port {port}: TIMEOUT (pas de réponse) - Probablement filtré ou machine inactive")
                    
                    elif reponse.haslayer(TCP):
                        flags = reponse[TCP].flags
                        if flags == 0x12:  # SYN-ACK (port ouvert)
                            print(f"✅ Port {port}: OUVERT")
                            ports_ouverts.append(port)
                            send(IP(dst=ip)/TCP(dport=port, flags="R"), verbose=False)
                        elif flags == 0x14:  # RST-ACK (port fermé)
                            print(f"❌ Port {port}: FERMÉ")
                        else:
                            print(f"⚠️ Port {port}: Réponse TCP inattendue (flags: {bin(flags)[2:]})")
                    
                    elif reponse.haslayer(ICMP):
                        icmp_type = reponse[ICMP].type
                        if icmp_type == 3:
                            print(f"🚫 Port {port}: FILTRÉ (ICMP type 3)")
                        else:
                            print(f"🚫 Port {port}: FILTRÉ (ICMP type {icmp_type})")
                    
                    else:
                        print(f"⚠️ Port {port}: Réponse inconnue (layer: {reponse.summary()})")

            elif choice_cmd == 2:
                try:
                    def is_valid_ip(ip):
                        """Vérifie si une adresse IP est valide (format x.x.x.x avec 0-255 par octet)"""
                        pattern = re.compile(r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
                        return bool(pattern.match(ip))

                    while True:
                        ip_dst_handcraft = simpledialog.askstring("IP Target", "Choisissez votre cible => IP dst")
                        if ip_dst_handcraft is None:
                            print("Aucune IP saisie.")
                        elif not is_valid_ip(ip_dst_handcraft):
                            print("IP target is not correct")
                        else:
                            print("IP dst seems good !")
                            break

                    print(f"Envoi d'un paquet ICMP: ping -c 1 {ip_dst_handcraft}")
                    messagebox.showinfo("Info", f"Envoi d'un paquet ICMP: ping -c 1 {ip_dst_handcraft}")
                    
                    pkt = IP(dst=ip_dst_handcraft)/ICMP()
                    reponse = sr1(pkt, timeout=2, verbose=False)
                    
                    if reponse:
                        print(width * "#")
                        print()
                        print(f"✅ Réponse reçue de : {reponse[IP].src}")
                        print(f"Type ICMP : {reponse[ICMP].type}")
                        print()
                        print(width * "#")
                    else:
                        print("❌ Pas de réponse reçue")
                        
                except Exception as e:
                    print(f"Erreur : {e}")
                    
            elif choice_cmd == 3:
                print("Sniff scapy = tcpdump -i eth0 -c 3 -v 80")
                messagebox.showinfo("Info", "Sniff scapy = tcpdump -i eth0 -c 3 -v 80")

                system = platform.system()

                if system in ["Linux", "Darwin"]:
                    print("Interfaces disponibles :")
                    for iface_name, iface_obj in conf.ifaces.items():
                        print(f"  - {iface_name}: {iface_obj.ip}")
                else:
                    print("Couldn't works with your system...")
                    sys.exit(1)

                while True:
                    iface = simpledialog.askstring("Interface internet", "iface (ex: en1, eth0, enp2s0):")
                    if iface is None:
                        print("iface is undefined")
                    elif iface in conf.ifaces:
                        print("iface => ok")
                        break
                    else:
                        print(f"Interface {iface} non trouvée")
                    
                def is_valid_ip_target(ip):
                    """Vérifie si une adresse IP est valide (format x.x.x.x avec 0-255 par octet)"""
                    pattern = re.compile(r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                                        r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                                        r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                                        r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
                    return bool(pattern.match(ip))

                while True:
                    ip_cible = simpledialog.askstring("IP Target", "Choisissez votre cible => IP dst")
                    if ip_cible is None:
                        print("Aucune IP saisie.")
                    elif not is_valid_ip_target(ip_cible):
                        print("IP target is not correct")
                    else:
                        print("IP dst seems good !")
                        break

                while True:
                    port_cible = simpledialog.askstring("Port cible (optionnel)", "Port à filtrer (ex: 80, 443, laisser vide):", initialvalue="")
                    if port_cible is None:
                        print("Aucun port saisi")
                        break
                    elif port_cible == "":
                        print("Aucun filtre de port - tous les ports seront scannés")
                        port_cible = None
                        break
                    elif port_cible.isdigit():
                        port_cible = int(port_cible)
                        if 1 <= port_cible <= 65535:
                            print(f"Port {port_cible} seems good !")
                            break
                        else:
                            print("Port invalide : doit être entre 1 et 65535")
                    else:
                        print("Erreur : veuillez entrer un nombre valide (ex: 80, 443) ou laisser vide")

                tuto_info = messagebox.showinfo("Info", "Il faut se rendre sur le site pendant le scan => http://scanme.nmap.org/")
                
                # TCP Filter Implementation
                filtre = "tcp"
                if ip_cible and ip_cible.strip():
                    filtre += f" and host {ip_cible}"
                if port_cible is not None:
                    filtre += f" and port {port_cible}"
                
                print(f"📡 Commande équivalente: tcpdump -i {iface} {filtre} -c 3 -v")
                print(f"🎯 Capture de 3 paquets TCP...\n")
                
                paquets_tcp = []
                
                def callback(packet):
                    if packet.haslayer(TCP) and len(paquets_tcp) < 3:
                        paquets_tcp.append(packet)
                        
                        print(f"\n{'='*60}")
                        print(f"Paquet TCP #{len(paquets_tcp)}")
                        print(f"{'='*60}")
                        print(f"  {packet[IP].src}:{packet[TCP].sport} → {packet[IP].dst}:{packet[TCP].dport}")
                        print(f"  Sequence: {packet[TCP].seq}")
                        print(f"  Acknowledge: {packet[TCP].ack}")
                        print(f"  Flags: {packet[TCP].flags}")
                        print(f"  Window: {packet[TCP].window}")
                        print(f"  Length: {len(packet)} bytes")
                        
                        return len(paquets_tcp) >= 3
                    return False
    
                try:
                    sniff(iface=iface, filter=filtre, prn=callback, store=False, timeout=10)
                    messagebox.showinfo("End", f"{len(paquets_tcp)}/3 paquets TCP capturés")
                except Exception as e:
                    messagebox.showerror("Erreur", str(e))
                    sys.exit(1)

            else:
                print("Vous n'avez pas choisi...")
                print("")
        else:
            print("Ok, à bientôt !")
            messagebox.showinfo("Au revoir", "Ok, à bientôt !")
            root.destroy()
            sys.exit(1)

    root.destroy()

if __name__ == "__main__":
    scanner()
