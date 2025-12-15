python
import nmap
import argparse
import sys
import socket
from datetime import datetime
from colorama import init, Fore, Style

# Initialisation de colorama pour les couleurs multi-plateformes
init(autoreset=True)

class Scanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.nm = nmap.PortScanner()
        
    def print_banner(self):
        print(Fore.CYAN + Style.BRIGHT + """
    ========================================
       PYRECON-LITE | CTF AUTOMATION TOOL
    ========================================
        """)

    def check_connection(self):
        """Vérifie si la cible répond au Ping"""
        print(Fore.YELLOW + f"[*] Vérification de la cible {self.target_ip}...")
        try:
            # On tente une simple connexion socket sur le port 80 ou ping
            # Ici on utilise nmap pour un ping scan simple (-sn)
            self.nm.scan(hosts=self.target_ip, arguments='-sn')
            if self.nm.all_hosts():
                print(Fore.GREEN + f"[+] Cible {self.target_ip} en ligne !")
                return True
            else:
                print(Fore.RED + "[-] La cible semble hors ligne ou bloque le ping.")
                # On demande à l'utilisateur s'il veut continuer quand même
                choice = input(Fore.YELLOW + "Voulez-vous forcer le scan ? (o/N) : ")
                return choice.lower() == 'o'
        except Exception as e:
            print(Fore.RED + f"[!] Erreur : {e}")
            return False

    def scan_ports(self):
        """Lance un scan de ports et de versions"""
        print(Fore.BLUE + "\n[*] Démarrage du scan Nmap (Top 1000 ports + Services)...")
        print(Fore.BLUE + "[*] Cela peut prendre une minute, patientez...")
        
        start_time = datetime.now()
        
        try:
            # -sV : Version detection
            # -T4 : Timing template (rapide)
            # --open : Montre seulement les ports ouverts
            arguments = '-sV -T4 --open'
            
            self.nm.scan(self.target_ip, arguments=arguments)
            
            # Analyse des résultats
            if self.target_ip in self.nm.all_hosts():
                for proto in self.nm[self.target_ip].all_protocols():
                    print(Fore.MAGENTA + f"\n[+] Protocole : {proto.upper()}")
                    
                    ports = self.nm[self.target_ip][proto].keys()
                    for port in sorted(ports):
                        service = self.nm[self.target_ip][proto][port]
                        state = service['state']
                        name = service['name']
                        version = service['version']
                        
                        # Affichage propre
                        print(f"    - Port {port}/{proto} : {Fore.GREEN}{state.upper()}{Style.RESET_ALL}")
                        print(f"      Service : {name}")
                        if version:
                            print(f"      Version : {Fore.CYAN}{version}")
            else:
                print(Fore.RED + "[-] Aucun résultat retourné par Nmap.")

        except Exception as e:
            print(Fore.RED + f"[!] Erreur durant le scan : {e}")
            print(Fore.YELLOW + "Astuce : Avez-vous lancé le script avec 'sudo' ?")
            sys.exit(1)
            
        duration = datetime.now() - start_time
        print(Fore.GREEN + f"\n[V] Scan terminé en {duration}")

def main():
    parser = argparse.ArgumentParser(description="Outil de reconnaissance simple pour CTF")
    parser.add_argument("ip", help="Adresse IP de la machine cible")
    args = parser.parse_args()

    scanner = Scanner(args.ip)
    scanner.print_banner()
    
    if scanner.check_connection():
        scanner.scan_ports()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interruption utilisateur.")
        sys.exit()