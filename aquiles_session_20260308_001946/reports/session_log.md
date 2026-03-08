# Aquiles Session Log — 20260308_001946
Started: 2026-03-08T00:19:46.772120
Assessment: Web Application Assessment
Targets: salesos.ciklo.me, 1-65535

## Command History

### [2026-03-08T00:21:14.186538] gobuster_dns
```
$ gobuster dns -d salesos.ciklo.me -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 20 -o /home/kali/yeah/aquiles_session_20260308_001946/outputs/phase2_gobuster_dns_1772950814.txt
Exit Code: 0
Duration: 59.6s
Output: /home/kali/yeah/aquiles_session_20260308_001946/outputs/phase2_gobuster_dns_1772950814.txt
```

### [2026-03-08T00:22:13.362137] gobuster_dns
```
$ gobuster dns -d 1-65535 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 20 -o /home/kali/yeah/aquiles_session_20260308_001946/outputs/phase2_gobuster_dns_1772950874.txt
Exit Code: 0
Duration: 59.2s
Output: /home/kali/yeah/aquiles_session_20260308_001946/outputs/phase2_gobuster_dns_1772950874.txt
```
