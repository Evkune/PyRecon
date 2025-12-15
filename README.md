# PyRecon 🛡️

**PyRecon** est un outil d'automatisation de reconnaissance réseau développé en Python. Il est conçu pour simplifier la phase initiale des CTF sur des plateformes comme Hack The Box ou autres.

Ce projet a été réalisé dans un but pédagogique pour approfondir mes compétences en développement Python et en méthodologie de reconnaissance active.

## 🚀 Fonctionnalités

- **Vérification de la cible** : Test de connectivité (Ping ICMP).
- **Scan de ports rapide** : Utilisation de Nmap pour identifier les ports ouverts (Top 1000).
- **Détection de services** : Identification des versions de services (bannières).
- **Rapport CLI** : Affichage coloré et structuré des résultats dans le terminal.

## 📋 Prérequis

- Python 3.x
- Nmap installé sur la machine (`sudo apt install nmap` sur Linux)

## 🛠️ Installation

1. Cloner le dépôt :
   ```bash
   git clone https://github.com/Evkune/PyRecon.git
   cd PyRecon
   ```

2. Installer les dépendances Python :
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Utilisation

Lancer le script avec les privilèges root (souvent nécessaire pour les scans SYN de Nmap) :
   ```bash
   sudo python3 main.py <IP_CIBLE>
   ```

Exemple :
   ```bash
   sudo python3 main.py 10.10.10.27
   ```

## 🚧 Roadmap / Améliorations futures

- Support du multi-threading pour accélérer les scans.
- Mode "Stealth" pour réduire l'empreinte réseau 

## ⚠️ Disclaimer

Cet outil est destiné uniquement à des fins éducatives et pour des tests sur des systèmes autorisés (CTF, laboratoires locaux). L'auteur décline toute responsabilité en cas de mauvaise utilisation sur des cibles non autorisées.