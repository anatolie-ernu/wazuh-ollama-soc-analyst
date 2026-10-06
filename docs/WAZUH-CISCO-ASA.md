# Wazuh all-in-one și Cisco ASA

Acest ghid adaugă stack-ului PoC Sentinel instalarea Wazuh Server all-in-one și traseul:

`Cisco ASA --syslog UDP/514--> Wazuh Manager --alerte JSON--> Sentinel API`

ASA trimite evenimentele syslog; Wazuh decodează evenimentele și aplică regulile. Sentinel primește **alertele** produse de Wazuh (nu fluxul brut), apoi face trierea AI și păstrează cazurile în MariaDB. Analiza AI rămâne consultativă; integrarea nu schimbă configurația firewall-ului și nu aplică blocări.

## Înainte de instalare

- Debian 13 Trixie, host amd64 cu IP static și acces root/sudo.
- Pentru PoC comun Wazuh + MariaDB + API + Ollama: pornește de la 8 vCPU, 24–32 GB RAM și spațiu SSD suficient (cel puțin 150 GB recomandat). Dimensionează după numărul de agenți, retenție, mărimea indexului și model. Ollama pe CPU poate fi lent; GPU este opțional.
- Configurează DNS/NTP și rezervă IP-ul management pentru ASA și IP-ul Wazuh.
- Salvează accesul administrativ Wazuh și backup-ul config-ului înainte de conectarea unui firewall de producție.

**Compatibilitate:** Wazuh 4.14 publică pachete Debian amd64 și instalatorul asistat all-in-one, însă Debian 13 nu apare în lista OS-urilor recomandate a quickstart-ului curent. Scriptul de mai jos folosește instalatorul oficial 4.14, dar validează-l întâi într-un VM Debian 13 și verifică documentația Wazuh aferentă versiunii înainte de producție. Nu îl considera certificare de suport vendor pentru această combinație.

## 1. Instalează proiectul Sentinel

Urmează [INSTALLATION.md](INSTALLATION.md) pentru Docker, MariaDB și aplicația Sentinel. Implicit API-ul ascultă numai pe loopback `127.0.0.1:8080`, deci integrarea pe același host poate folosi HTTP local. Dacă API-ul rulează pe alt host, folosește FQDN-ul HTTPS valid al acelui host în `SENTINEL_HOOK_URL`, permite conexiunea în firewall și instalează certificatul CA de încredere pe serverul Wazuh.

## 2. Instalează Wazuh all-in-one

Clonează repo-ul și rulează instalatorul pe Debian 13:

```bash
git clone https://github.com/anatolie-ernu/wazuh-ollama-soc-analyst.git
cd wazuh-ollama-soc-analyst
sudo bash scripts/install-wazuh-debian13.sh
```

Scriptul descarcă assistant-ul oficial din ramura `4.14`, instalează managerul, indexerul și dashboard-ul pe același host, verifică serviciile și protejează logul/arhiva cu parole. Arhiva `wazuh-install-files.tar` conține credențiale privilegiate; copiaz-o într-un secret manager și șterge copia de pe host după ce verifici recuperabilitatea. Dashboard: `https://<IP_WAZUH>/` (certificatul inițial poate fi self-signed).

Verifică:

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard --no-pager
sudo ss -lntup
```

Păstrează dashboard/API Wazuh, indexer 9200 și porturile de management accesibile doar din rețelele administrative. Nu publica indexerul pe Internet.

## 3. Configurează Wazuh să asculte syslog ASA

Rulează receiver-ul pe serverul Wazuh. Setează IP-ul ASA sau CIDR-ul **cât mai restrâns**. `allowed-ips` este filtrul Wazuh; UFW, dacă este activ, primește și regula cu aceeași sursă.

```bash
sudo ASA_ALLOWED_IPS='192.0.2.20' \
  WAZUH_LISTEN_IP='192.0.2.10' \
  bash scripts/configure-wazuh-asa-syslog.sh
```

Înlocuiește IP-urile cu valorile tale. `WAZUH_LISTEN_IP` este adresa locală Wazuh pe interfața de management a ASA; omite variabila dacă dorești bind pe toate interfețele, deși este preferabilă o adresă dedicată. Scriptul implicit folosește UDP/514, validează XML, păstrează backup `ossec.conf.sentinel-backup` și repornește managerul. Dacă portul ori protocolul se schimbă, configurează ASA identic. Pentru TCP, Cisco ASA folosește implicit portul 1470; porturile TCP personalizate trebuie să fie între 1025 și 65535. Configurează Wazuh cu `WAZUH_SYSLOG_PROTOCOL=tcp WAZUH_SYSLOG_PORT=1470` și ASA cu `logging host <INTERFAȚĂ> <IP_WAZUH> tcp/1470`. Scriptul respinge TCP/514. ASA trimite către un server pe UDP sau TCP, nu ambele simultan. TCP oferă livrare cu transport fiabil, dar unele versiuni ASA blochează sesiuni noi când serverul syslog nu este disponibil; verifică opțiunea `logging permit-hostdown` și politica locală înainte de activare.

Firewall-ul de rețea trebuie să permită numai `ASA_IP -> WAZUH_IP:514/UDP`. Verifică listener-ul și logurile după test:

```bash
sudo ss -lunp | grep ':514'
sudo tail -f /var/ossec/logs/archives/archives.json
```

Arhivarea brută depinde de `logall_json` și spațiul disponibil; pentru confirmarea alertelor folosește și `/var/ossec/logs/alerts/alerts.json`. Activează arhivele numai cu retenție și capacitate de stocare planificate.

## 4. Configurează Cisco ASA

Exemplul este în [config/cisco-asa/syslog-config.example.txt](../config/cisco-asa/syslog-config.example.txt). Am preluat ghidul ASA din repository-ul [wazuh-asa-siem-stack](https://github.com/anatolie-ernu/wazuh-asa-siem-stack), dar am adaptat comenzile la listener-ul direct Wazuh și am eliminat valorile fixe.

Verifică numele interfeței de egress și versiunea ASA; nivelul `informational` generează volum mare. Ajustează `logging trap` și clasele de evenimente conform politicii locale. Nu am preluat `format emblem` din exemplul vechi, ca să păstrăm syslog standard pentru decoder-ele Wazuh; nu am preluat `logging facility LOCAL7`, fiindcă ASA cere un număr de facilitate 16–23 (implicit 20). Mărirea buffer-ului intern la 2 MB este opțională și poate șterge buffer-ul existent, deci nu este setată de exemplu.

```text
configure terminal
logging enable
logging timestamp
logging device-id hostname
logging trap informational
logging host <ASA_EGRESS_INTERFACE> <WAZUH_MANAGER_IP> udp/514
end
write memory
show logging
logging test
```

Începe cu UDP/514 și testează livrarea înainte de a schimba protocolul. Verifică manualul exact al modelului/versiunii și nu copia o comandă de `logging host` până nu ai completat interfața și IP-ul corect.

Repository-ul sursă include și reguli personalizate, verificare NetFlow și un script de conectivitate. Nu le-am copiat automat: NetFlow este alt flux decât syslog, iar regulile folosesc câmpuri/formatări care trebuie validate cu mesajele ASA reale și `/var/ossec/bin/wazuh-logtest` înainte de activare. Testul de rețea din acest proiect verifică direct listener-ul și arhivele Wazuh, fără IP-uri prestabilite.

## 5. Trimite alertele Wazuh în Sentinel

Configurează endpointul API Sentinel, apoi instalează integrarea custom pe manager. Scriptul citește cheia `INGEST_API_KEY` din fișierul `.env` fără să o afișeze și o scrie în blocul de integrare Wazuh, deci păstrează `ossec.conf` cu acces root-only și backup-uri protejate.

```bash
sudo SENTINEL_ENV_FILE=/opt/sentinel-l1/.env \
  SENTINEL_HOOK_URL='http://127.0.0.1:8080/api/v1/alerts' \
  SENTINEL_ALERT_LEVEL=5 \
  bash scripts/configure-wazuh-sentinel-integration.sh
```

HTTP este acceptat numai către loopback; traficul nu părăsește hostul. Pentru alt host, endpointul trebuie să fie HTTPS cu certificat verificat de sistem; portul 8080 nu trebuie expus extern. Pragul 5 trimite orice alertă Wazuh de nivel 5 sau mai mare (nu doar ASA), deoarece decodorul/regulile active determină grupurile de alertă. Inspectează întâi regulile tale dacă dorești filtrare strictă pe ASA și setează un filtru `group` sau `rule_id` potrivit versiunii/regulilor tale.

Verifică după un test:

```bash
sudo tail -f /var/ossec/logs/integrations.log
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

Poți testa receptorul fără firewall cu exemplul `curl` din README. Folosește o alertă sintetică și nu divulga cheia în history-ul shell-ului.

## 6. Diagnosticare și rollback

- Nu apar pachete: verifică VLAN/rutare, ACL, interfața ASA și `sudo tcpdump -ni any udp port 514` pe Wazuh.
- Pachete fără alerte: verifică `allowed-ips`, formatul syslog, `archives.json`, apoi validează un mesaj cu `/var/ossec/bin/wazuh-logtest`. Nu presupune că orice mesaj Cisco este automat alertă.
- Alerte fără caz Sentinel: verifică TLS/CA, URL, `integrations.log`, cheia API și `/var/log`/logurile containerului API.
- Restaurare receiver: revizuiește backup-ul, apoi `sudo cp -a /var/ossec/etc/ossec.conf.sentinel-backup /var/ossec/etc/ossec.conf && sudo systemctl restart wazuh-manager`. Backup-ul poate conține și setări locale, nu îl restaura peste modificări ulterioare fără comparație.
- Dezactivare rapidă: oprește log forwarding pe ASA sau elimină doar blocul marcat `managed-by: sentinel-l1-asa-syslog`/`sentinel-l1-api-integration`, apoi validează și repornește managerul.

Integrarea este unidirecțională pentru ingestie și triere. Nu instalează Active Response, nu blochează IP-uri și nu modifică configurația ASA în mod automat.
