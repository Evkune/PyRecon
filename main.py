import nmap
import argparse
import sys
import socket
import requests
import ftplib
from datetime import datetime
from colorama import init, Fore, Style

# Initialisation de colorama
init(autoreset=True)

class Logger:
    """Classe utilitaire pour gérer l'affichage et l'enregistrement dans un fichier"""
    def __init__(self, ip):
        self.filename = f"scan_report_{ip}.txt"
        self.clean_file()
    
    def clean_file(self):
        with open(self.filename, 'w') as f:
            f.write(f"--- RAPPORT DE SCAN : {datetime.now()} ---\n\n")

    def log(self, message, color=Fore.WHITE):
        """Affiche en couleur dans la console et en brut dans le fichier"""
        # Affichage console
        print(color + message)
        # Enregistrement fichier (on retire les codes couleurs ANSI pour que ce soit lisible)
        clean_message = message + "\n"
        with open(self.filename, 'a') as f:
            f.write(clean_message)

class Scanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.nm = nmap.PortScanner()
        self.logger = Logger(target_ip)
        
    def print_banner(self):
        banner = """
    ========================================
       PYRECON v1.2 | CTF TOOLKIT
    ========================================
        """
        self.logger.log(banner, Fore.CYAN + Style.BRIGHT)

    def check_connection(self):
        self.logger.log(f"[*] Vérification de la cible {self.target_ip}...", Fore.YELLOW)
        try:
            self.nm.scan(hosts=self.target_ip, arguments='-sn')
            if self.nm.all_hosts():
                self.logger.log(f"[+] Cible {self.target_ip} en ligne !", Fore.GREEN)
                return True
            else:
                self.logger.log("[-] La cible semble hors ligne.", Fore.RED)
                return False
        except Exception as e:
            self.logger.log(f"[!] Erreur : {e}", Fore.RED)
            return False

    def check_ftp_anonymous(self):
        """Tente une connexion FTP Anonyme (Classique sur HTB)"""
        self.logger.log("\n[*] Test FTP Anonyme...", Fore.BLUE)
        try:
            ftp = ftplib.FTP(self.target_ip, timeout=5)
            ftp.login('anonymous', 'anonymous')
            self.logger.log(f"[!!!] SUCCÈS : Connexion FTP Anonyme autorisée !", Fore.GREEN + Style.BRIGHT)
            self.logger.log(f"      Message : {ftp.getwelcome()}", Fore.GREEN)
            try:
                files = ftp.nlst()
                self.logger.log(f"      Fichiers trouvés : {files}", Fore.CYAN)
            except:
                pass
            ftp.quit()
        except Exception:
            self.logger.log("[-] Pas d'accès FTP Anonyme.", Fore.WHITE)

    def check_http_recon(self, port):
        """Récupère le titre, le serveur et robots.txt"""
        self.logger.log(f"\n[*] Inspection Web rapide sur le port {port}...", Fore.BLUE)
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{self.target_ip}:{port}"
        
        try:
            # Récupération des headers et du contenu
            r = requests.get(url, timeout=3, verify=False) # verify=False pour ignorer les erreurs SSL self-signed
            
            # 1. Server Header
            server = r.headers.get('Server', 'Inconnu')
            self.logger.log(f"[+] Serveur Web : {server}", Fore.GREEN)
            
            # 2. Titre de la page (Parsing simple)
            if '<title>' in r.text:
                title = r.text.split('<title>')[1].split('</title>')[0]
                self.logger.log(f"[+] Titre de la page : {title.strip()}", Fore.GREEN)
            
            # 3. Robots.txt
            r_robots = requests.get(f"{url}/robots.txt", timeout=3, verify=False)
            if r_robots.status_code == 200:
                self.logger.log(f"[+] Robots.txt trouvé ! (Contient {len(r_robots.text.splitlines())} lignes)", Fore.YELLOW)
            else:
                self.logger.log("[-] Pas de robots.txt", Fore.WHITE)
                
        except requests.exceptions.RequestException:
            self.logger.log(f"[-] Impossible de contacter le service Web.", Fore.RED)

    def scan_ports(self):
        self.logger.log("\n[*] Démarrage du scan Nmap (Top 1000 ports)...", Fore.BLUE)
        start_time = datetime.now()
        
        try:
            # Scan standard
            self.nm.scan(self.target_ip, arguments='-sV -T4 --open')
            
            if self.target_ip in self.nm.all_hosts():
                for proto in self.nm[self.target_ip].all_protocols():
                    ports = sorted(self.nm[self.target_ip][proto].keys())
                    
                    for port in ports:
                        service = self.nm[self.target_ip][proto][port]
                        self.logger.log(f"\n[+] Port {port}/{proto} OUVERT : {service['name']} {service['version']}", Fore.GREEN)
                        
                        # --- DÉCLENCHEURS INTELLIGENTS ---
                        if port == 21:
                            self.check_ftp_anonymous()
                        if port in [80, 443, 8080]:
                            self.check_http_recon(port)
                            
            else:
                self.logger.log("[-] Aucun port ouvert détecté.", Fore.RED)

        except Exception as e:
            self.logger.log(f"[!] Erreur Nmap : {e}", Fore.RED)
            sys.exit(1)
            
        duration = datetime.now() - start_time
        self.logger.log(f"\n[V] Scan terminé en {duration}", Fore.GREEN)
        self.logger.log(f"[i] Rapport sauvegardé dans {self.logger.filename}", Fore.MAGENTA)

def main():
    parser = argparse.ArgumentParser(description="Outil de reconnaissance pour CTF")
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
