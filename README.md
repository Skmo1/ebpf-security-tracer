# ebpf-security-tracer

Real-time Linux syscall tracer for security monitoring using eBPF.

Un traceur léger basé sur **eBPF** qui surveille en temps réel les appels
`execve()` et les connexions réseau sortantes (`connect()`), et alerte
lorsqu'un même processus exécute un programme puis ouvre une connexion
réseau dans une courte fenêtre de temps — un pattern classique de
**reverse shell** / **exécution de malware**.

Ce projet est un point de départ (starter) pensé pour être étendu :
observabilité, détection d'anomalies, ou base pour un outil de sécurité
plus complet.

> **Note technique** : ce projet utilise **libbpf + CO-RE** plutôt que
> **BCC**. BCC compile le code eBPF à la volée avec clang, ce qui demande
> d'embarquer clang/LLVM sur la machine cible — lourd pour un outil de
> sécurité qu'on veut déployer largement. CO-RE compile une seule fois et
> tourne sur n'importe quel kernel compatible BTF, sans dépendance runtime.

## Comment ça marche

- Un programme **eBPF en C** (compilé en CO-RE, `Compile Once – Run
  Everywhere`) s'attache à :
  - un **tracepoint** sur `sys_enter_execve`
  - un **kprobe** sur `tcp_v4_connect`
- Chaque événement est envoyé au userspace via un **ring buffer**.
- Un programme **Go** (avec [cilium/ebpf](https://github.com/cilium/ebpf))
  charge le programme eBPF, lit les événements, et déclenche une alerte si
  un `execve` est suivi d'un `connect` du même PID en moins de 5 secondes.

## Prérequis

- Linux kernel ≥ 5.8 avec support BTF (`/sys/kernel/btf/vmlinux` doit exister)
- `clang`, `llvm`, `libbpf-dev`
- `bpftool`
- Go ≥ 1.22

Sur Ubuntu/Debian :

```bash
sudo apt install clang llvm libbpf-dev linux-tools-$(uname -r) linux-tools-common
```

## Installation et lancement

```bash
git clone https://github.com/Skmo1/ebpf-security-tracer.git
cd ebpf-security-tracer

# 1. Génère vmlinux.h depuis le kernel local
make vmlinux

# 2. Génère le code Go lié au programme eBPF (bpf2go)
make generate

# 3. Build et lance (root requis pour charger un programme eBPF)
make run
```

## Exemple de sortie

```
Détecteur eBPF démarré. Ctrl+C pour arrêter.
[EXEC] pid=48213 ppid=1022 comm=bash file=/bin/nc
[CONNECT] pid=48213 comm=nc dst=203.0.113.42:4444
  ⚠️  ALERTE: pid=48213 (nc) a exécuté un programme puis ouvert une
      connexion réseau en moins de 5s — pattern suspect
```

## Roadmap / idées d'extension

- [ ] Support IPv6
- [ ] Filtrage par liste blanche de binaires connus
- [ ] Export des alertes vers un webhook / Slack
- [ ] Détection additionnelle : lecture de fichiers sensibles
      (`/etc/shadow`, clés SSH) après une connexion réseau
- [ ] Dashboard web (Grafana / simple UI) pour visualiser les événements
- [ ] Tests unitaires + tests d'intégration avec un environnement kernel
      dans une VM/CI

## Licence

MIT pour le code userspace. Le code eBPF (`bpf/detector.bpf.c`) est sous
GPL-2.0, requis par le kernel Linux pour utiliser certains helpers eBPF.

## Avertissement

Projet éducatif. Ne pas déployer en production sans audit de sécurité et
tests approfondis.
