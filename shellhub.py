#!/usr/bin/env python3

import socket
import ssl
import threading
import os
import sys
import select
import termios
import tty
import time
import subprocess
import shutil
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import argparse
import readline

# ====== CONFIGURACIÓN SIN LISTENERS POR DEFECTO ======
CONFIG = {
    "LISTEN_DEFAULT": [],  # Lista vacía - sin listeners por defecto
    "CERT_DIR": "./certs",
    "SESSIONS_DIR": "./sessions", 
    "LOGS_DIR": "./logs",
    "HEARTBEAT_INTERVAL": 15.0,
    "SOCKET_BACKLOG": 50,
    "COMMAND_TIMEOUT": 10.0,
    "RECV_BUFFER_SIZE": 8192,
    "HISTORY_FILE": "./.shellhub_history"
}

# ====== SETUP DE LOGGING ======
def setup_logging():
    """Configura sistema de logging profesional"""
    os.makedirs(CONFIG["LOGS_DIR"], exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(CONFIG["LOGS_DIR"], "shellhub.log")),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger('ShellHub')

logger = setup_logging()

# ====== CONFIGURACIÓN DEL ENTORNO ======
def setup_environment():
    """Configura el entorno necesario"""
    # Crear directorios requeridos
    for directory in [CONFIG["CERT_DIR"], CONFIG["SESSIONS_DIR"], CONFIG["LOGS_DIR"]]:
        os.makedirs(directory, exist_ok=True)
    
    # Verificar dependencias
    if not shutil.which("openssl"):
        logger.warning("OpenSSL no encontrado. Las funciones TLS no estarán disponibles.")

# ====== COLORES Y FORMATO ======
class Colors:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    @classmethod
    def success(cls, msg):
        return f"{cls.GREEN}{cls.BOLD}[+]{cls.RESET} {msg}"
    
    @classmethod
    def error(cls, msg):
        return f"{cls.RED}{cls.BOLD}[-]{cls.RESET} {msg}"
    
    @classmethod
    def warning(cls, msg):
        return f"{cls.YELLOW}{cls.BOLD}[!]{cls.RESET} {msg}"
    
    @classmethod
    def info(cls, msg):
        return f"{cls.CYAN}{cls.BOLD}[*]{cls.RESET} {msg}"

# ====== DETECCIÓN DE SISTEMA OPERATIVO MEJORADA ======
class OSDetector:
    """Detecta el sistema operativo de la sesión remota de manera más precisa"""
    
    @staticmethod
    def detect_os(session) -> str:
        """
        Detecta el sistema operativo enviando comandos de prueba
        Retorna: 'windows', 'linux', 'unknown'
        """
        # Primero probar comandos Linux (más comunes en entornos Unix)
        linux_commands = [
            ("uname -s", "linux"),           # Sistema operativo
            ("ls /", "linux"),               # Listar directorio raíz
            ("which bash", "linux"),         # Verificar bash
            ("echo $SHELL", "linux"),        # Shell actual
        ]
        
        for cmd, expected_os in linux_commands:
            if OSDetector._test_command(session, cmd, expected_os):
                return "linux"
        
        # Luego probar comandos Windows
        windows_commands = [
            ("ver", "windows"),              # Versión de Windows
            ("cmd /c ver", "windows"),       # Versión alternativa
            ("dir", "windows"),              # Listar directorio
            ("echo %OS%", "windows"),        # Variable de entorno OS
        ]
        
        for cmd, expected_os in windows_commands:
            if OSDetector._test_command(session, cmd, expected_os):
                return "windows"
        
        return "unknown"
    
    @staticmethod
    def _test_command(session, command: str, expected_os: str) -> bool:
        """Prueba si un comando es reconocido por el sistema remoto"""
        try:
            marker = f"__DETECT_{os.urandom(4).hex()}__"
            
            # Formatear comando según el OS esperado
            if expected_os == "linux":
                test_cmd = f"echo '{marker}' && {command} 2>&1\n"
            else:  # windows
                test_cmd = f"echo {marker} && {command} 2>&1\n"
            
            if not session.send(test_cmd.encode()):
                return False
            
            # Esperar respuesta
            buffer = b""
            start_time = time.time()
            session.sock.settimeout(1.0)
            
            while time.time() - start_time < 3.0:
                try:
                    data = session.sock.recv(4096)
                    if not data:
                        break
                    buffer += data
                    
                    # Verificar si tenemos el marker
                    if marker.encode() in buffer:
                        output = buffer.decode('utf-8', errors='ignore')
                        
                        # Verificaciones específicas por OS
                        if expected_os == "linux":
                            # Para Linux, verificar respuestas típicas
                            if "Linux" in output or "GNU" in output or "bash" in output:
                                return True
                            # Si el comando se ejecutó sin error, probablemente es Linux
                            if command in ["uname -s", "ls /", "which bash"] and "not found" not in output:
                                return True
                                
                        elif expected_os == "windows":
                            # Para Windows, buscar indicadores
                            if "Microsoft" in output or "Windows" in output or "OS]" in output:
                                return True
                            # Comandos dir y ver generalmente funcionan solo en Windows
                            if command in ["ver", "dir"] and "not found" not in output:
                                return True
                                
                except socket.timeout:
                    continue
                except Exception:
                    break
                    
        except Exception:
            pass
            
        return False

# ====== GESTIÓN DE CERTIFICADOS ======
class CertificateManager:
    """Gestiona certificados SSL/TLS de manera más robusta"""
    
    @staticmethod
    def create_self_signed_cert(name: str, days: int = 365) -> Tuple[bool, str]:
        """Crea certificado autofirmado con mejores opciones"""
        crt_path = os.path.join(CONFIG["CERT_DIR"], f"{name}.crt")
        key_path = os.path.join(CONFIG["CERT_DIR"], f"{name}.key")
        
        if not shutil.which("openssl"):
            return False, "openssl no encontrado en el sistema"
        
        # Comando más robusto para generar certificados
        cmd = [
            "openssl", "req", "-x509", "-nodes",
            "-days", str(days),
            "-newkey", "rsa:4096",  # Clave más segura
            "-keyout", key_path,
            "-out", crt_path,
            "-subj", f"/CN={name}/O=ShellHub/C=US"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30  # Timeout para evitar bloqueos
            )
            
            if result.returncode == 0:
                # Verificar que los archivos se crearon correctamente
                if os.path.exists(crt_path) and os.path.exists(key_path):
                    return True, f"Certificado creado: {crt_path}, {key_path}"
                else:
                    return False, "Error: archivos de certificado no creados"
            else:
                return False, f"openssl error: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return False, "Timeout generando certificado"
        except Exception as e:
            return False, f"Error inesperado: {e}"
    
    @staticmethod
    def list_certificates() -> List[str]:
        """Lista certificados disponibles"""
        try:
            certs = []
            for file in os.listdir(CONFIG["CERT_DIR"]):
                if file.endswith(('.crt', '.pem', '.key')):
                    certs.append(file)
            return sorted(certs)
        except Exception as e:
            logger.error(f"Error listando certificados: {e}")
            return []
    
    @staticmethod
    def validate_certificate(name: str) -> bool:
        """Valida que un certificado exista y sea válido"""
        crt_path = os.path.join(CONFIG["CERT_DIR"], f"{name}.crt")
        key_path = os.path.join(CONFIG["CERT_DIR"], f"{name}.key")
        
        return os.path.exists(crt_path) and os.path.exists(key_path)

# ====== CLASES PRINCIPALES ======
class Session:
    """Clase para manejar sesiones de manera más organizada"""
    
    def __init__(self, sid: int, sock: socket.socket, addr: tuple, listener_lid: int):
        self.sid = sid
        self.sock = sock
        self.addr = addr
        self.listener_lid = listener_lid
        self.created = self._now()
        self.last_seen = self._now()
        self.alias = f"session-{sid}"
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.alive = True
        self.os_type = "unknown"  # Será detectado después
        self.shell_type = "basic" # basic, cmd, powershell, bash, etc.
        self.log_path = self._setup_logging()
        self.interactive_mode = False  # Controla si está en modo interactivo
        
        logger.info(Colors.success(f"Nueva sesión {sid} desde {addr}"))
        self._write_log(f"--- session {sid} start {self.created} from {addr}\n")
        
        # Detectar OS en segundo plano
        threading.Thread(target=self._detect_os_background, daemon=True).start()
    
    def _now(self) -> str:
        """Retorna timestamp UTC en formato ISO (corregido)"""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    def _setup_logging(self) -> str:
        """Crea archivo de log para la sesión"""
        log_file = f"session_{self.sid}_{self.addr[0]}_{self.addr[1]}.log"
        return os.path.join(CONFIG["SESSIONS_DIR"], log_file)
    
    def _write_log(self, data: bytes):
        """Escribe datos en el log de sesión"""
        try:
            with open(self.log_path, "ab") as f:
                if isinstance(data, str):
                    data = data.encode('utf-8', errors='ignore')
                f.write(data)
        except Exception as e:
            logger.error(f"Error escribiendo log: {e}")
    
    def _detect_os_background(self):
        """Detecta el OS en segundo plano"""
        try:
            detected_os = OSDetector.detect_os(self)
            self.os_type = detected_os
            
            # Detectar tipo de shell basado en el OS
            if detected_os == "windows":
                # Probar PowerShell primero, luego CMD
                if self._test_powershell():
                    self.shell_type = "powershell"
                else:
                    self.shell_type = "cmd"
            elif detected_os == "linux":
                # Probar diferentes shells Linux
                if self._test_shell("bash"):
                    self.shell_type = "bash"
                elif self._test_shell("zsh"):
                    self.shell_type = "zsh"
                else:
                    self.shell_type = "sh"
            
            logger.info(Colors.info(f"Sesión {self.sid} detectada: OS={detected_os}, Shell={self.shell_type}"))
            
        except Exception as e:
            logger.error(f"Error detectando OS para sesión {self.sid}: {e}")
    
    def _test_powershell(self) -> bool:
        """Verifica si PowerShell está disponible"""
        test_cmd = "powershell -c \"echo 'POWERSHELL_TEST'\"\n"
        marker = "POWERSHELL_TEST"
        
        try:
            if not self.send(test_cmd.encode()):
                return False
            
            buffer = b""
            start_time = time.time()
            self.sock.settimeout(2.0)
            
            while time.time() - start_time < 3.0:
                try:
                    data = self.sock.recv(4096)
                    if not data:
                        break
                    buffer += data
                    if marker.encode() in buffer:
                        return True
                except socket.timeout:
                    continue
                except Exception:
                    break
                    
        except Exception:
            pass
            
        return False
    
    def _test_shell(self, shell_name: str) -> bool:
        """Verifica si un shell específico está disponible en Linux"""
        test_cmd = f"which {shell_name} && echo 'SHELL_FOUND_{shell_name.upper()}'\n"
        marker = f"SHELL_FOUND_{shell_name.upper()}"
        
        try:
            if not self.send(test_cmd.encode()):
                return False
            
            buffer = b""
            start_time = time.time()
            self.sock.settimeout(2.0)
            
            while time.time() - start_time < 3.0:
                try:
                    data = self.sock.recv(4096)
                    if not data:
                        break
                    buffer += data
                    if marker.encode() in buffer:
                        return True
                except socket.timeout:
                    continue
                except Exception:
                    break
                    
        except Exception:
            pass
            
        return False
    
    def update_activity(self, rx: int = 0, tx: int = 0):
        """Actualiza estadísticas de actividad"""
        self.last_seen = self._now()
        self.rx_bytes += rx
        self.tx_bytes += tx
    
    def send(self, data: bytes) -> bool:
        """Envía datos de manera segura"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            self.sock.sendall(data)
            self.update_activity(tx=len(data))
            # No loggear en modo interactivo para evitar ruido
            if not self.interactive_mode:
                self._write_log(f"[SENT] {data}\n".encode())
            return True
        except Exception as e:
            logger.error(f"Error enviando datos a sesión {self.sid}: {e}")
            self.alive = False
            return False
    
    def close(self):
        """Cierra la sesión de manera limpia"""
        try:
            self.sock.close()
            self._write_log(f"--- session {self.sid} closed {self._now()}\n")
            logger.info(Colors.warning(f"Sesión {self.sid} cerrada"))
        except Exception as e:
            logger.error(f"Error cerrando sesión {self.sid}: {e}")
        finally:
            self.alive = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte la sesión a diccionario para mostrar"""
        return {
            "id": self.sid,
            "alias": self.alias,
            "address": f"{self.addr[0]}:{self.addr[1]}",
            "created": self.created,
            "last_seen": self.last_seen,
            "rx_bytes": self.rx_bytes,
            "tx_bytes": self.tx_bytes,
            "listener": self.listener_lid,
            "os": self.os_type,
            "shell": self.shell_type,
            "alive": self.alive
        }

class SessionManager:
    """Gestiona todas las sesiones activas"""
    
    def __init__(self):
        self.sessions: Dict[int, Session] = {}
        self.lock = threading.Lock()
        self.counter = 0
    
    def add_session(self, sock: socket.socket, addr: tuple, listener_lid: int) -> int:
        """Registra una nueva sesión"""
        with self.lock:
            self.counter += 1
            sid = self.counter
            session = Session(sid, sock, addr, listener_lid)
            self.sessions[sid] = session
            return sid
    
    def get_session(self, sid: int) -> Optional[Session]:
        """Obtiene una sesión por ID"""
        with self.lock:
            return self.sessions.get(sid)
    
    def remove_session(self, sid: int) -> bool:
        """Elimina una sesión"""
        with self.lock:
            session = self.sessions.get(sid)
            if session:
                session.close()
                del self.sessions[sid]
                return True
            return False
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """Lista todas las sesiones activas"""
        with self.lock:
            return [session.to_dict() for session in self.sessions.values()]
    
    def get_alive_sessions(self) -> List[int]:
        """Obtiene IDs de sesiones activas"""
        with self.lock:
            return [sid for sid, session in self.sessions.items() if session.alive]

# ====== GESTIÓN DE LISTENERS ======
class ListenerManager:
    """Gestiona listeners de manera más robusta"""
    
    def __init__(self, session_manager: SessionManager):
        self.listeners: Dict[int, Dict] = {}
        self.lock = threading.Lock()
        self.counter = 0
        self.session_manager = session_manager
        self.running = True
    
    def start_listener(self, host: str, port: int, use_tls: bool = False, cert_name: str = None) -> int:
        """Inicia un nuevo listener"""
        with self.lock:
            self.counter += 1
            lid = self.counter
            
            listener_info = {
                "id": lid,
                "host": host,
                "port": port,
                "tls": use_tls,
                "cert_name": cert_name,
                "socket": None,
                "thread": None,
                "active": True
            }
            
            self.listeners[lid] = listener_info
            
            # Iniciar thread del listener
            thread = threading.Thread(
                target=self._listener_thread,
                args=(listener_info,),
                daemon=True
            )
            listener_info["thread"] = thread
            thread.start()
            
            logger.info(Colors.success(f"Listener {lid} iniciado en {host}:{port} (TLS: {use_tls})"))
            return lid
    
    def _listener_thread(self, listener_info: Dict):
        """Thread que acepta conexiones entrantes"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                sock.bind((listener_info["host"], listener_info["port"]))
                sock.listen(CONFIG["SOCKET_BACKLOG"])
                listener_info["socket"] = sock
            except OSError as e:
                logger.error(Colors.error(f"No se pudo iniciar listener en {listener_info['host']}:{listener_info['port']}: {e}"))
                listener_info["active"] = False
                return
            
            # Configurar SSL si es necesario
            ssl_context = None
            if listener_info["tls"]:
                if not CertificateManager.validate_certificate(listener_info["cert_name"]):
                    logger.error(Colors.error(f"Certificado no válido: {listener_info['cert_name']}"))
                    listener_info["active"] = False
                    return
                
                try:
                    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    crt_path = os.path.join(CONFIG["CERT_DIR"], f"{listener_info['cert_name']}.crt")
                    key_path = os.path.join(CONFIG["CERT_DIR"], f"{listener_info['cert_name']}.key")
                    ssl_context.load_cert_chain(crt_path, key_path)
                except Exception as e:
                    logger.error(Colors.error(f"Error configurando SSL: {e}"))
                    listener_info["active"] = False
                    return
            
            # Bucle de aceptación de conexiones
            while self.running and listener_info["active"]:
                try:
                    sock.settimeout(1.0)
                    client_sock, addr = sock.accept()
                    
                    if listener_info["tls"] and ssl_context:
                        try:
                            client_sock = ssl_context.wrap_socket(client_sock, server_side=True)
                        except ssl.SSLError as e:
                            logger.error(Colors.error(f"Error SSL con {addr}: {e}"))
                            client_sock.close()
                            continue
                    
                    # Registrar nueva sesión
                    self.session_manager.add_session(client_sock, addr, listener_info["id"])
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(Colors.error(f"Error aceptando conexión: {e}"))
                    
        except Exception as e:
            logger.error(Colors.error(f"Error en listener {listener_info['id']}: {e}"))
        finally:
            try:
                if listener_info["socket"]:
                    listener_info["socket"].close()
            except:
                pass
            
            listener_info["active"] = False
            logger.info(Colors.warning(f"Listener {listener_info['id']} detenido"))
    
    def stop_listener(self, lid: int) -> bool:
        """Detiene un listener"""
        with self.lock:
            listener = self.listeners.get(lid)
            if not listener:
                return False
            
            listener["active"] = False
            try:
                if listener["socket"]:
                    listener["socket"].close()
            except:
                pass
            
            del self.listeners[lid]
            return True
    
    def list_listeners(self) -> List[Dict]:
        """Lista todos los listeners activos"""
        with self.lock:
            return [
                {
                    "id": info["id"],
                    "host": info["host"],
                    "port": info["port"],
                    "tls": info["tls"],
                    "cert_name": info["cert_name"],
                    "active": info["active"]
                }
                for info in self.listeners.values()
            ]

# ====== COMMAND HANDLER MEJORADO ======
class CommandHandler:
    """Maneja la ejecución de comandos con soporte multi-OS"""
    
    def __init__(self, session_manager):
        self.sessions = session_manager
    
    def execute_command(self, sid: int, command: str, timeout: float = None) -> Tuple[bool, str]:
        """Ejecuta un comando en una sesión específica"""
        if timeout is None:
            timeout = CONFIG["COMMAND_TIMEOUT"]
        
        session = self.sessions.get_session(sid)
        if not session or not session.alive:
            return False, "Sesión no existe o no está activa"
        
        # Generar marcadores únicos
        marker_start = f"__SH_START_{os.urandom(4).hex()}__"
        marker_end = f"__SH_END_{os.urandom(4).hex()}__"
        
        # Construir comando según el OS - CORREGIDO
        if session.os_type == "windows":
            if session.shell_type == "powershell":
                # PowerShell usa punto y coma
                full_command = f"echo '{marker_start}'; {command}; echo '{marker_end}'\n"
            else:
                # CMD usa &&
                full_command = f"echo {marker_start} && {command} && echo {marker_end}\n"
        else:
            # Linux/Unix - usar punto y coma
            full_command = f"echo '{marker_start}'; {command}; echo '{marker_end}'\n"
        
        if not session.send(full_command.encode()):
            return False, "Error enviando comando"
        
        # Recibir output
        buffer = b""
        start_time = time.time()
        session.sock.settimeout(0.5)
        
        while time.time() - start_time < timeout:
            try:
                data = session.sock.recv(CONFIG["RECV_BUFFER_SIZE"])
                if not data:
                    break
                buffer += data
                session.update_activity(rx=len(data))
                
                # Verificar si tenemos ambos marcadores
                if marker_start.encode() in buffer and marker_end.encode() in buffer:
                    break
                    
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Error recibiendo datos: {e}")
                break
        
        try:
            output = buffer.decode('utf-8', errors='ignore')
            if marker_start in output and marker_end in output:
                # Extraer solo el output del comando - CORREGIDO
                parts = output.split(marker_start)
                if len(parts) > 1:
                    command_output = parts[1].split(marker_end)[0]
                    # Limpiar el output - remover ecos de los marcadores
                    lines = command_output.strip().split('\n')
                    # Filtrar líneas que contengan los marcadores
                    clean_lines = [line for line in lines if marker_start not in line and marker_end not in line]
                    result = '\n'.join(clean_lines).strip()
                    return True, result
                return False, "Formato de respuesta inválido"
            else:
                return False, "Timeout o marcadores no encontrados"
        except Exception as e:
            return False, f"Error procesando respuesta: {e}"
    
    def execute_all(self, command: str) -> Dict[int, Tuple[bool, str]]:
        """Ejecuta comando en todas las sesiones activas - CORREGIDO"""
        results = {}
        sids = self.sessions.get_alive_sessions()
        
        if not sids:
            return results
        
        def worker(sid):
            try:
                success, output = self.execute_command(sid, command)
                results[sid] = (success, output)
            except Exception as e:
                results[sid] = (False, f"Error: {e}")
        
        threads = []
        for sid in sids:
            t = threading.Thread(target=worker, args=(sid,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Esperar a que todos terminen con timeout
        for t in threads:
            t.join(timeout=CONFIG["COMMAND_TIMEOUT"] + 5)
        
        return results

# ====== MODO INTERACTIVO MEJORADO ======
class InteractiveSession:
    """Maneja sesiones TTY interactivas con soporte multi-OS"""
    
    def __init__(self, session_manager):
        self.sessions = session_manager
    
    def start(self, sid: int):
        """Inicia sesión interactiva"""
        session = self.sessions.get_session(sid)
        if not session:
            print(Colors.error("Sesión no existe"))
            return
        
        # Limpiar cualquier dato pendiente en el buffer
        self._clear_socket_buffer(session)
        
        # Solo mejorar la shell si no está ya en un shell interactivo
        if session.shell_type == "basic":
            if not self._upgrade_shell(session):
                print(Colors.warning("No se pudo mejorar la shell, continuando en modo básico"))
        
        print(Colors.success(f"Controlando sesión {sid} ({session.os_type}/{session.shell_type}) - Ctrl+D para salir"))
        
        # Marcar sesión como interactiva
        session.interactive_mode = True
        try:
            self._run_interactive(session)
        finally:
            # Restaurar modo normal
            session.interactive_mode = False
    
    def _clear_socket_buffer(self, session: Session):
        """Limpia el buffer del socket antes de iniciar modo interactivo"""
        try:
            session.sock.settimeout(0.1)
            while True:
                data = session.sock.recv(4096)
                if not data:
                    break
        except:
            pass
        finally:
            session.sock.settimeout(1.0)
    
    def _upgrade_shell(self, session: Session) -> bool:
        """Mejora la shell según el sistema operativo"""
        
        if session.os_type == "linux":
            return self._upgrade_linux_shell(session)
        elif session.os_type == "windows":
            return self._upgrade_windows_shell(session)
        else:
            # OS desconocido, probar diferentes métodos
            return self._upgrade_unknown_shell(session)
    
    def _upgrade_linux_shell(self, session: Session) -> bool:
        """Mejora shell en sistemas Linux/Unix"""
        upgrade_methods = [
            # Método 1: Python pty (más efectivo)
            "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
            
            # Método 2: script command
            "script -qc /bin/bash /dev/null",
            
            # Método 3: bash simple con opciones interactivas
            "/bin/bash -i",
            
            # Método 4: solo cambiar a bash
            "bash",
        ]
        
        for method in upgrade_methods:
            if session.send(f"{method}\n".encode()):
                time.sleep(0.5)
                # Limpiar buffer de entrada
                self._clear_socket_buffer(session)
                return True
        return False
    
    def _upgrade_windows_shell(self, session: Session) -> bool:
        """Mejora shell en sistemas Windows"""
        
        # Intentar PowerShell primero si está disponible
        if session.shell_type == "powershell":
            upgrade_commands = [
                # PowerShell interactivo completo
                "powershell -NoExit -Command \"Set-ExecutionPolicy Bypass -Scope Process -Force\"",
                "powershell -NoExit",
            ]
        else:
            # CMD normal
            upgrade_commands = [
                "cmd /k",
            ]
        
        for cmd in upgrade_commands:
            if session.send(f"{cmd}\n".encode()):
                time.sleep(0.5)
                # Limpiar buffer
                self._clear_socket_buffer(session)
                return True
        return False
    
    def _upgrade_unknown_shell(self, session: Session) -> bool:
        """Intenta mejorar shell en OS desconocido"""
        methods = [
            # Probamos métodos Linux primero
            "python3 -c 'import pty; pty.spawn(\"/bin/sh\")'",
            "python -c 'import pty; pty.spawn(\"/bin/sh\")'",
            "script -qc /bin/sh /dev/null",
            
            # Luego métodos Windows
            "powershell -NoExit",
            "cmd /k",
            
            # Finalmente shells simples
            "bash -i",
            "sh -i",
        ]
        
        for method in methods:
            if session.send(f"{method}\n".encode()):
                time.sleep(0.5)
                # Limpiar buffer
                self._clear_socket_buffer(session)
                return True
        return False
    
    def _run_interactive(self, session: Session):
        """Bucle principal interactivo"""
        old_attrs = self._set_raw_mode()
        
        try:
            session.sock.setblocking(False)
            
            while session.alive:
                # Leer de socket y stdin
                rlist, _, _ = select.select([session.sock, sys.stdin], [], [], 0.1)
                
                for ready in rlist:
                    if ready == session.sock:
                        # Datos desde la sesión remota
                        try:
                            data = session.sock.recv(CONFIG["RECV_BUFFER_SIZE"])
                            if not data:
                                print(Colors.error("\nConexión cerrada por el remoto"))
                                return
                            os.write(sys.stdout.fileno(), data)
                            session.update_activity(rx=len(data))
                        except BlockingIOError:
                            pass
                        except Exception as e:
                            print(Colors.error(f"\nError de conexión: {e}"))
                            return
                    
                    elif ready == sys.stdin:
                        # Datos desde teclado local
                        try:
                            data = sys.stdin.read(1)
                            if not data or data == '\x04':  # Ctrl+D
                                print(Colors.info("\nSaliendo de sesión interactiva..."))
                                return
                            session.send(data.encode())
                        except Exception as e:
                            print(Colors.error(f"\nError enviando datos: {e}"))
                            return
                            
        except KeyboardInterrupt:
            print(Colors.warning("\nInterrumpido por usuario"))
        finally:
            self._restore_mode(old_attrs)
            print(Colors.info("Sesión interactiva terminada"))
    
    def _set_raw_mode(self):
        """Configura terminal en modo raw"""
        old_attrs = termios.tcgetattr(sys.stdin.fileno())
        tty.setraw(sys.stdin.fileno())
        return old_attrs
    
    def _restore_mode(self, old_attrs):
        """Restaura configuración del terminal"""
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_attrs)

# ====== SHELLHUB CLI MEJORADA ======
class ShellHubCLI:
    """Interfaz de línea de comandos mejorada con soporte multi-OS"""
    
    def __init__(self):
        self.session_manager = SessionManager()
        self.listener_manager = ListenerManager(self.session_manager)
        self.command_handler = CommandHandler(self.session_manager)
        self.interactive = InteractiveSession(self.session_manager)
        self.cert_manager = CertificateManager()
        
        self._setup_completion()
        self._setup_commands()
    
    def _setup_completion(self):
        """Configura autocompletado de comandos"""
        try:
            readline.parse_and_bind("tab: complete")
            readline.set_completer(self._completer)
            # Cargar historial si existe
            if os.path.exists(CONFIG["HISTORY_FILE"]):
                readline.read_history_file(CONFIG["HISTORY_FILE"])
        except Exception:
            pass  # Autocompletado no disponible
    
    def _completer(self, text, state):
        """Función de autocompletado"""
        options = [cmd for cmd in self.commands.keys() if cmd.startswith(text)]
        if state < len(options):
            return options[state]
        return None
    
    def _setup_commands(self):
        """Configura los comandos disponibles"""
        self.commands = {
            "help": self.cmd_help,
            "listeners": self.cmd_listeners,
            "sessions": self.cmd_sessions,
            "info": self.cmd_info,
            "use": self.cmd_use,
            "exec": self.cmd_exec,
            "runall": self.cmd_runall,
            "kill": self.cmd_kill,
            "rename": self.cmd_rename,
            "cert": self.cmd_cert,
            "listener": self.cmd_listener,
            "clear": self.cmd_clear,
            "exit": self.cmd_exit,
            "quit": self.cmd_exit,
            "detect": self.cmd_detect,
        }

    def _print_banner(self):
        """Muestra banner de la aplicación"""
        banner = f"""
{Colors.RED}{Colors.BOLD}
  █████████  █████               ████  ████  █████   █████            █████    
 ███▒▒▒▒▒███▒▒███               ▒▒███ ▒▒███ ▒▒███   ▒▒███            ▒▒███     
▒███    ▒▒▒  ▒███████    ██████  ▒███  ▒███  ▒███    ▒███  █████ ████ ▒███████ 
▒▒█████████  ▒███▒▒███  ███▒▒███ ▒███  ▒███  ▒███████████ ▒▒███ ▒███  ▒███▒▒███
 ▒▒▒▒▒▒▒▒███ ▒███ ▒███ ▒███████  ▒███  ▒███  ▒███▒▒▒▒▒███  ▒███ ▒███  ▒███ ▒███
 ███    ▒███ ▒███ ▒███ ▒███▒▒▒   ▒███  ▒███  ▒███    ▒███  ▒███ ▒███  ▒███ ▒███
▒▒█████████  ████ █████▒▒██████  █████ █████ █████   █████ ▒▒████████ ████████ 
 ▒▒▒▒▒▒▒▒▒  ▒▒▒▒ ▒▒▒▒▒  ▒▒▒▒▒▒  ▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒   ▒▒▒▒▒▒▒▒ ▒▒▒▒▒▒▒▒   v1.0
{Colors.RESET}
{Colors.CYAN}{Colors.BOLD}                      --- by b4d1t :D---{Colors.RESET}
"""
        print(banner)

    def run(self):
        """Ejecuta la shell interactiva"""
        self._print_banner()
        print(Colors.info("Escribe 'help' para ver los comandos disponibles"))
        print(Colors.warning("No hay listeners por defecto. Usa 'listener add' para crear uno."))
        
        # Bucle principal REPL
        while True:
            try:
                prompt = f"{Colors.CYAN}{Colors.BOLD}ShellHub{Colors.RESET} >> "
                cmd_line = input(prompt).strip()
                
                if not cmd_line:
                    continue
                
                # Guardar en historial
                try:
                    readline.write_history_file(CONFIG["HISTORY_FILE"])
                except:
                    pass
                
                self._execute_command(cmd_line)
                
            except KeyboardInterrupt:
                print("\n" + Colors.warning("Use 'exit' para salir"))
            except EOFError:
                print()
                self.cmd_exit()
            except Exception as e:
                logger.error(f"Error en REPL: {e}")
    
    def _execute_command(self, cmd_line: str):
        """Ejecuta un comando"""
        parts = cmd_line.split()
        cmd_name = parts[0].lower()
        
        if cmd_name in self.commands:
            try:
                self.commands[cmd_name](parts[1:])
            except Exception as e:
                print(Colors.error(f"Error ejecutando comando: {e}"))
        else:
            print(Colors.error(f"Comando desconocido: {cmd_name}"))

    # ====== IMPLEMENTACIÓN DE COMANDOS ======
    
    def cmd_help(self, args):
        """Muestra ayuda de comandos"""
        help_text = f"""
╔═══════════════════════════ ${Colors.CYAN}${Colors.BOLD}AYUDA SHELLHUB${Colors.RESET} ═══════════════════════════╗
{Colors.info("Listeners:")}
{Colors.info("")}   {Colors.CYAN}listeners{Colors.RESET}              - Listar listeners activos
{Colors.info("")}   {Colors.CYAN}listener add HOST PORT [TLS CERT]{Colors.RESET} - Agregar listener
{Colors.info("")}   {Colors.CYAN}listener stop ID{Colors.RESET}        - Detener listener

{Colors.info("Certificados:")}
{Colors.info("")}   {Colors.CYAN}cert create NAME{Colors.RESET}        - Crear certificado autofirmado
{Colors.info("")}   {Colors.CYAN}cert list{Colors.RESET}              - Listar certificados

{Colors.info("Sesiones:")}
{Colors.info("")}   {Colors.CYAN}sessions{Colors.RESET}               - Listar sesiones activas
{Colors.info("")}   {Colors.CYAN}info ID{Colors.RESET}                - Información detallada de sesión
{Colors.info("")}   {Colors.CYAN}use ID{Colors.RESET}                 - Sesión interactiva TTY
{Colors.info("")}   {Colors.CYAN}exec ID COMANDO{Colors.RESET}        - Ejecutar comando en sesión
{Colors.info("")}   {Colors.CYAN}runall COMANDO{Colors.RESET}         - Ejecutar en todas las sesiones
{Colors.info("")}   {Colors.CYAN}kill ID{Colors.RESET}                - Cerrar sesión
{Colors.info("")}   {Colors.CYAN}rename ID ALIAS{Colors.RESET}        - Renombrar sesión
{Colors.info("")}   {Colors.CYAN}detect ID{Colors.RESET}              - Forzar detección de OS

{Colors.info("Utilidades:")}
{Colors.info("")}   {Colors.CYAN}clear{Colors.RESET}                  - Limpiar pantalla
{Colors.info("")}   {Colors.CYAN}exit / quit{Colors.RESET}            - Salir
╚══════════════════════════════════════════════════════════════════════════╝
"""
        print(help_text)
    
    def cmd_listeners(self, args):
        """Lista listeners activos"""
        listeners = self.listener_manager.list_listeners()
        if not listeners:
            print(Colors.warning("No hay listeners activos. Usa 'listener add' para crear uno."))
            return
        
        print(f"{Colors.CYAN}{'ID':<4} {'Host':<15} {'Port':<6} {'TLS':<6} {'Certificado':<15} {'Estado':<10}{Colors.RESET}")
        print("-" * 70)
        for listener in listeners:
            status = "ACTIVO" if listener["active"] else "DETENIDO"
            cert = listener["cert_name"] or "N/A"
            print(f"{listener['id']:<4} {listener['host']:<15} {listener['port']:<6} "
                  f"{str(listener['tls']):<6} {cert:<15} {status:<10}")
    
    def cmd_sessions(self, args):
        """Lista sesiones activas con información de OS"""
        sessions = self.session_manager.list_sessions()
        if not sessions:
            print(Colors.warning("No hay sesiones activas"))
            return
        
        print(f"{Colors.CYAN}{'ID':<4} {'Alias':<18} {'Dirección':<21} {'OS':<8} {'Shell':<12} {'RX/TX':<12} {'Listener':<8}{Colors.RESET}")
        print("-" * 100)
        for session in sessions:
            rx_tx = f"{session['rx_bytes']}/{session['tx_bytes']}"
            status = "ACTIVA" if session["alive"] else "MUERTA"
            os_display = session['os'][:7] if session['os'] != "unknown" else "???"
            shell_display = session['shell'][:10] if session['shell'] != "basic" else "basic"
            
            print(f"{session['id']:<4} {session['alias']:<18} {session['address']:<21} "
                  f"{os_display:<8} {shell_display:<12} {rx_tx:<12} {session['listener']:<8} {status}")
    
    def cmd_info(self, args):
        """Muestra información detallada de una sesión"""
        if not args:
            print(Colors.error("Uso: info <id>"))
            return
        
        try:
            sid = int(args[0])
            session = self.session_manager.get_session(sid)
            if not session:
                print(Colors.error("Sesión no encontrada"))
                return
            
            info = session.to_dict()
            print(f"""
{Colors.CYAN}Información de Sesión {sid}:{Colors.RESET}
  ID:          {info['id']}
  Alias:       {info['alias']}
  Dirección:   {info['address']}
  Creada:      {info['created']}
  Última vez:  {info['last_seen']}
  Bytes RX:    {info['rx_bytes']}
  Bytes TX:    {info['tx_bytes']}
  Listener:    {info['listener']}
  OS:          {info['os']}
  Shell:       {info['shell']}
  Estado:      {'ACTIVA' if info['alive'] else 'INACTIVA'}
  Log file:    {session.log_path}
            """)
            
        except ValueError:
            print(Colors.error("ID debe ser un número"))
    
    def cmd_use(self, args):
        """Inicia sesión interactiva"""
        if not args:
            print(Colors.error("Uso: use <id>"))
            return
        
        try:
            sid = int(args[0])
            self.interactive.start(sid)
        except ValueError:
            print(Colors.error("ID debe ser un número"))
    
    def cmd_exec(self, args):
        """Ejecuta comando en sesión"""
        if len(args) < 2:
            print(Colors.error("Uso: exec <id> <comando>"))
            return
        
        try:
            sid = int(args[0])
            command = " ".join(args[1:])
            
            success, output = self.command_handler.execute_command(sid, command)
            
            if success:
                print(Colors.success(f"Output de sesión {sid}:"))
                print(output)
            else:
                print(Colors.error(f"Error: {output}"))
                
        except ValueError:
            print(Colors.error("ID debe ser un número"))
    
    def cmd_runall(self, args):
        """Ejecuta comando en todas las sesiones - CORREGIDO"""
        if not args:
            print(Colors.error("Uso: runall <comando>"))
            return
        
        command = " ".join(args)
        print(Colors.info(f"Ejecutando '{command}' en todas las sesiones activas..."))
        
        results = self.command_handler.execute_all(command)
        
        if not results:
            print(Colors.warning("No hay sesiones activas para ejecutar el comando"))
            return
        
        success_count = 0
        for sid, (success, output) in results.items():
            if success:
                success_count += 1
                print(Colors.success(f"\n--- Sesión {sid} ---"))
                if output:
                    print(output)
                else:
                    print("(sin output)")
            else:
                print(Colors.error(f"\n--- Sesión {sid} (Error) ---"))
                print(output)
        
        print(Colors.info(f"\nComando ejecutado en {success_count}/{len(results)} sesiones exitosamente"))
    
    def cmd_kill(self, args):
        """Cierra una sesión"""
        if not args:
            print(Colors.error("Uso: kill <id>"))
            return
        
        try:
            sid = int(args[0])
            if self.session_manager.remove_session(sid):
                print(Colors.success(f"Sesión {sid} cerrada"))
            else:
                print(Colors.error("Sesión no encontrada"))
        except ValueError:
            print(Colors.error("ID debe ser un número"))
    
    def cmd_rename(self, args):
        """Renombra una sesión"""
        if len(args) < 2:
            print(Colors.error("Uso: rename <id> <nuevo_alias>"))
            return
        
        try:
            sid = int(args[0])
            new_alias = " ".join(args[1:])
            
            session = self.session_manager.get_session(sid)
            if session:
                session.alias = new_alias
                print(Colors.success(f"Sesión {sid} renombrada a: {new_alias}"))
            else:
                print(Colors.error("Sesión no encontrada"))
        except ValueError:
            print(Colors.error("ID debe ser un número"))

    def cmd_detect(self, args):
        """Fuerza detección de OS en una sesión"""
        if not args:
            print(Colors.error("Uso: detect <id>"))
            return
        
        try:
            sid = int(args[0])
            session = self.session_manager.get_session(sid)
            if not session:
                print(Colors.error("Sesión no encontrada"))
                return
            
            print(Colors.info(f"Detectando OS para sesión {sid}..."))
            old_os = session.os_type
            old_shell = session.shell_type
            
            # Forzar redetección
            detected_os = OSDetector.detect_os(session)
            session.os_type = detected_os
            
            # Redetectar shell
            if detected_os == "windows":
                if session._test_powershell():
                    session.shell_type = "powershell"
                else:
                    session.shell_type = "cmd"
            elif detected_os == "linux":
                if session._test_shell("bash"):
                    session.shell_type = "bash"
                elif session._test_shell("zsh"):
                    session.shell_type = "zsh"
                else:
                    session.shell_type = "sh"
            else:
                session.shell_type = "basic"
            
            print(Colors.success(f"Detección completada:"))
            print(f"  OS: {old_os} -> {session.os_type}")
            print(f"  Shell: {old_shell} -> {session.shell_type}")
            
        except ValueError:
            print(Colors.error("ID debe ser un número"))
    
    def cmd_cert(self, args):
        """Gestiona certificados"""
        if not args:
            print(Colors.error("Uso: cert <create|list> [nombre]"))
            return
        
        subcmd = args[0].lower()
        
        if subcmd == "create":
            if len(args) < 2:
                print(Colors.error("Uso: cert create <nombre>"))
                return
            
            name = args[1]
            success, message = self.cert_manager.create_self_signed_cert(name)
            
            if success:
                print(Colors.success(message))
            else:
                print(Colors.error(message))
        
        elif subcmd == "list":
            certs = self.cert_manager.list_certificates()
            if certs:
                print(Colors.success("Certificados disponibles:"))
                for cert in certs:
                    print(f"  {cert}")
            else:
                print(Colors.warning("No hay certificados"))
        
        else:
            print(Colors.error("Subcomando desconocido. Use: create | list"))
    
    def cmd_listener(self, args):
        """Gestiona listeners"""
        if not args:
            print(Colors.error("Uso: listener <add|stop> ..."))
            return
        
        subcmd = args[0].lower()
        
        if subcmd == "add":
            if len(args) < 3:
                print(Colors.error("Uso: listener add <host> <port> [tls] [cert_name]"))
                return
            
            host = args[1]
            try:
                port = int(args[2])
            except ValueError:
                print(Colors.error("Puerto debe ser un número"))
                return
            
            use_tls = len(args) > 3 and args[3].lower() in ("tls", "true", "1")
            cert_name = args[4] if len(args) > 4 else None
            
            if use_tls and not cert_name:
                print(Colors.error("TLS requiere nombre de certificado"))
                return
            
            lid = self.listener_manager.start_listener(host, port, use_tls, cert_name)
            if lid:
                print(Colors.success(f"Listener {lid} iniciado en {host}:{port}"))
            else:
                print(Colors.error("No se pudo iniciar el listener"))
        
        elif subcmd == "stop":
            if len(args) < 2:
                print(Colors.error("Uso: listener stop <id>"))
                return
            
            try:
                lid = int(args[1])
                if self.listener_manager.stop_listener(lid):
                    print(Colors.success(f"Listener {lid} detenido"))
                else:
                    print(Colors.error("Listener no encontrado"))
            except ValueError:
                print(Colors.error("ID debe ser un número"))
        
        else:
            print(Colors.error("Subcomando desconocido. Use: add | stop"))
    
    def cmd_clear(self, args):
        """Limpia la pantalla"""
        os.system("clear")
    
    def cmd_exit(self, args=None):
        """Sale de la aplicación"""
        print(Colors.info("Cerrando ShellHub..."))
        
        # Detener todos los listeners
        listeners = self.listener_manager.list_listeners()
        for listener in listeners:
            self.listener_manager.stop_listener(listener["id"])
        
        # Cerrar todas las sesiones
        sessions = self.session_manager.list_sessions()
        for session in sessions:
            self.session_manager.remove_session(session["id"])
        
        print(Colors.success("¡Hasta luego!"))
        sys.exit(0)

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description="ShellHub - Multi-OS Remote Administration Tool")
    parser.add_argument("--no-default-listeners", action="store_true", 
                       help="No iniciar listeners por defecto (ya no hay por defecto)")
    
    args = parser.parse_args()
    
    # Configurar entorno
    setup_environment()
    
    try:
        # Iniciar CLI
        cli = ShellHubCLI()
        
        # Ejecutar interfaz
        cli.run()
        
    except KeyboardInterrupt:
        print(Colors.info("\nInterrumpido por usuario"))
    except Exception as e:
        logger.error(f"Error fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
