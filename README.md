# Backrooms

> Red Team Network Toolkit with a Honeypot Labyrinth

**Backrooms** est un framework red team réseau écrit en Python. Son concept
central : déployer un **labyrinthe de machines factices** (honeypots) autour de
ton réseau réel — exactement comme dans les backrooms, un attaquant qui s'y
aventure se **perd** dans des faux services et de faux systèmes pendant que
toutes ses actions sont loggées et analysées.

## Modules

| Command | Description |
|---------|-------------|
| `backrooms scan hosts 192.168.1.0/24` | Découverte d'hôtes actifs |
| `backrooms scan ports 192.168.1.10 -p 1-1000` | Scan de ports + détection de services |
| `backrooms scan full 192.168.1.0/24` | Scan complet : hosts, ports, services, OS |
| `backrooms tui` | Dashboard interactif |
| `backrooms honeypot deploy --config config.yaml` | *(bientôt)* Déployer le labyrinthe de honeypots |

## Installation

```bash
pip install -e .
```

## Utilisation rapide

```bash
backrooms -q scan full 192.168.1.0/24 --ports "21,22,80,443,445,3389"
backrooms scan ports 10.0.0.5 -p 1-1024 --type connect
backrooms tui
```

## Sécurité & légalité

Cet outil est conçu pour l'éducation, les CTF et l'évaluation sécuritaire de
réseaux que tu possèdes. L'utiliser contre un réseau sans autorisation est
illicite. Tu es seul responsable de ton usage.

## Roadmap

- [x] CLI + module scanner (hosts, ports, services, OS)
- [ ] TUI dashboard (en cours)
- [ ] Module MITM (ARP spoofing, DNS spoofing, sniffing)
- [ ] Module SMB (enum shares, users)
- [ ] Module wireless (evil twin, deauth)
- [ ] Honeypot core (fake SSH/HTTP/SMB via Docker)
- [ ] Labyrinthe (redirection entre fausses machines)
- [ ] IDS + logging des actions attaquant