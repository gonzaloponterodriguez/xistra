"""
CybersecuritySentinel
                                                                 
1. CAJA NEGRA DIGITAL (DLT)  — Registro inmutable de telemetría        
     · Cadena de bloques ligera (SHA-256 Merkle hash-chain)              
     · Cada bloque = hash del anterior + timestamp + datos + firma       
     · Múltiples validadores (quórum ≥ 2/3) simulados en Edge           
                                                                          
2. HPE SILICON ROOT OF TRUST  — Verificación firmware                  
     · Medición de hash de firmware contra PCR en TPM 2.0               
     · Cadena de confianza: BIOS  Bootloader  OS  Aplicaciones       
     · Política de atestación remota (HPE iLO 6 + Trusted Boot)         
                                                                          
3. MODO SEGURO (SafeMode Protocol)                                      
     · Detección de telemetría contradictoria inyectada                  
     · Aislamiento automático de sistemas críticos CAN/OBD               
     · Control manual verificado por biometría (huella + iris)           

"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import statistics
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Optional


# CONSTANTES GLOBALES

DLT_HMAC_SECRET        = b"IGNIS_SENTINEL_DLT_SECRET_K3Y_v1"  # Prod: desde HSM iLO 6
QUORUM_VALIDATORS      = 3          # Número de nodos validadores Edge simulados
QUORUM_THRESHOLD       = 2          # Mínimo para consenso (2 de 3)
FIRMWARE_BASELINE_HASH = "a3f8c1d2e9b47605f2a1c8d3e4b56789012345678901234567890abcdef012345"  # SHA-256 PCR0
BIOMETRIC_HMAC_SECRET  = b"BIOAUTH_IGNIS_SENTINEL_IRIS_HUELLAS"
TELEMETRY_CONTRADICTION_THRESHOLD = 3   # Nº anomalías simultáneas  Modo Seguro
SAFE_MODE_TIMEOUT_SECONDS         = 300  # 5 min en Safe Mode sin bio-auth  alerta escalada


# ENUMERACIONES

class BlockType(Enum):
    TELEMETRY     = "TELEMETRY"
    ALERT         = "ALERT"
    FIRMWARE_CHECK = "FIRMWARE_CHECK"
    SAFE_MODE_EVENT = "SAFE_MODE_EVENT"
    BIOMETRIC_AUTH = "BIOMETRIC_AUTH"


class TrustLevel(Enum):
    TRUSTED     = "TRUSTED"      # Firmware verificado, TPM válido
    DEGRADED    = "DEGRADED"     # Advertencia menor, continuar con monitorización
    COMPROMISED = "COMPROMISED"  # Firmware alterado — iniciar protocolo emergencia
    UNKNOWN     = "UNKNOWN"      # No se pudo verificar (fallo de sensor TPM)


class SystemMode(Enum):
    OPERATIONAL  = "OPERATIONAL"    # Modo normal, gemelo digital activo
    ALERT        = "ALERT"          # Anomalías detectadas, modo reforzado
    SAFE_MODE    = "SAFE_MODE"      # Aislamiento sistema crítico, control manual
    LOCKDOWN     = "LOCKDOWN"       # Bloqueo total, solo comandos firmados biométricamente


class ContradictionType(Enum):
    FUEL_PHYSICS_MISMATCH    = "FUEL_PHYSICS_MISMATCH"    # Consumo vs RPM incoherente
    GPS_VELOCITY_MISMATCH    = "GPS_VELOCITY_MISMATCH"    # Posición GPS vs odómetro
    PRESSURE_FLOW_MISMATCH   = "PRESSURE_FLOW_MISMATCH"   # Presión bomba vs caudal
    THERMAL_SENSOR_CONFLICT  = "THERMAL_SENSOR_CONFLICT"  # Temperatura sensor A vs B
    CAN_REPLAY_DETECTED      = "CAN_REPLAY_DETECTED"      # Mensaje CAN repetido
    SEQUENCE_ANOMALY         = "SEQUENCE_ANOMALY"          # Salto anómalo en secuencia


# DATACLASSES

@dataclass
class DLTBlock:
    """
    Bloque de la Caja Negra Digital (DLT ligera).
    Implementa una hash-chain SHA-256 con firma HMAC por bloque.
    Estructura inspirada en Hyperledger Fabric pero sin overhead de smart contracts.
    """
    index: int
    timestamp_utc: str
    block_type: str                      # BlockType.value
    payload: dict                        # Datos del bloque (telemetría, alerta, etc.)
    previous_hash: str                   # Hash del bloque anterior (cadena inmutable)
    nonce: str = ""                      # Nonce aleatorio anti-duplicación
    block_hash: str = ""                 # SHA-256(prev_hash + timestamp + payload + nonce)
    hmac_signature: str = ""             # HMAC-SHA256 firmado con clave DLT_HMAC_SECRET
    validator_signatures: dict = field(default_factory=dict)  # {validator_id: HMAC}
    consensus_reached: bool = False

    def compute_hash(self) -> str:
        """Calcula el hash del bloque (sin incluir block_hash ni HMAC en el cálculo)."""
        content = json.dumps({
            "index": self.index,
            "timestamp_utc": self.timestamp_utc,
            "block_type": self.block_type,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
        }, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(content.encode()).hexdigest()

    def sign(self, secret: bytes = DLT_HMAC_SECRET) -> str:
        """Genera firma HMAC-SHA256 del hash del bloque."""
        return hmac.new(secret, self.block_hash.encode(), hashlib.sha256).hexdigest()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FirmwareMeasurement:
    """
    Resultado de verificación de firmware usando HPE Silicon Root of Trust.
    Simula el proceso de atestación remota del TPM 2.0 vía HPE iLO 6.
    """
    component: str           # "BIOS", "BOOTLOADER", "OS_KERNEL", "IGNIS_APP"
    measured_hash: str       # PCR value leído del TPM
    baseline_hash: str       # Hash de referencia (golden measurement)
    trust_level: TrustLevel
    measurement_time: str
    ilo_session_id: str = ""  # ID de sesión HPE iLO 6
    pcr_index: int = 0       # Índice del PCR del TPM (0=BIOS, 4=MBR, 8=OS)
    attestation_report: dict = field(default_factory=dict)

    @property
    def is_trusted(self) -> bool:
        return self.trust_level == TrustLevel.TRUSTED

    def to_dict(self) -> dict:
        d = asdict(self)
        d['trust_level'] = self.trust_level.value
        return d


@dataclass
class BiometricToken:
    """
    Token de autenticación biométrica para control manual verificado.
    Simula verificación dual: huella dactilar (sensor capacitivo) + iris (NIR).
    """
    operator_id: str
    fingerprint_hash: str    # SHA-256 de la plantilla de huella dactilar
    iris_hash: str           # SHA-256 de la plantilla de iris NIR
    timestamp: str
    token_hmac: str = ""     # HMAC que vincula ambas biometrías + operator_id + timestamp
    is_valid: bool = False
    auth_method: str = "FINGERPRINT+IRIS"  # Método de autenticación multifactor

    def compute_token_hmac(self) -> str:
        data = f"{self.operator_id}:{self.fingerprint_hash}:{self.iris_hash}:{self.timestamp}"
        return hmac.new(BIOMETRIC_HMAC_SECRET, data.encode(), hashlib.sha256).hexdigest()

    def verify(self) -> bool:
        """Verifica integridad del token biométrico."""
        expected = self.compute_token_hmac()
        return hmac.compare_digest(expected, self.token_hmac)


@dataclass
class TelemetryContradiction:
    """Registro de una contradicción detectada en la telemetría."""
    contradiction_type: ContradictionType
    description: str
    sensor_a_value: Any
    sensor_b_value: Any
    delta_percent: float
    timestamp: str
    severity: int  # 1=leve, 2=moderado, 3=crítico


@dataclass
class SafeModeEvent:
    """Evento de activación/desactivación del Modo Seguro."""
    event_type: str          # "ACTIVATION", "DEACTIVATION", "LOCKDOWN"
    trigger_contradictions: list
    timestamp: str
    biometric_auth: Optional[dict] = None
    operator_id: str = ""
    isolated_systems: list = field(default_factory=list)
    manual_override_commands: list = field(default_factory=list)


# 1. CAJA NEGRA DIGITAL (DLT Hash-Chain)

class DigitalBlackBox:
    """
    Caja Negra Digital.

    Implementa una DLT ligera (Distributed Ledger Technology) mediante hash-chain
    SHA-256 con consenso de múltiples validadores Edge. Cada bloque referencia
    al anterior, haciendo imposible la manipulación retroactiva sin invalidar
    toda la cadena posterior.

    Arquitectura de validadores (3 nodos Edge en el camión):
      - VAL-EDGE-01: HPE Edgeline EL8000 (procesador principal)
      - VAL-EDGE-02: HPE ProLiant MicroServer (redundante)
      - VAL-EDGE-03: HPE Aruba AP (nodo de red, validador ligero)

    Anti-manipulación:
      1. Hash chain: alterar bloque N invalida todos los bloques N+1..∞
      2. HMAC per-bloque: firma con clave almacenada en TPM (no accesible en runtime)
      3. Quórum 2/3: se requieren ≥2 validadores para confirmar cada bloque
      4. Timestamp monotónico: previene inserción de bloques en el pasado
    """

    GENESIS_HASH = "0" * 64  # Hash del bloque génesis

    def __init__(self, truck_id: str):
        self.truck_id = truck_id
        self.chain: list[DLTBlock] = []
        self.validator_ids = ["VAL-EDGE-01", "VAL-EDGE-02", "VAL-EDGE-03"]
        self._last_timestamp_ns: int = 0  # Monotónico anti-replay

        # Crear bloque génesis
        self._create_genesis_block()

    def _create_genesis_block(self) -> None:
        genesis = DLTBlock(
            index=0,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            block_type=BlockType.TELEMETRY.value,
            payload={"genesis": True, "truck_id": self.truck_id, "version": "1.0"},
            previous_hash=self.GENESIS_HASH,
            nonce=secrets.token_hex(16),
        )
        genesis.block_hash = genesis.compute_hash()
        genesis.hmac_signature = genesis.sign()
        genesis.validator_signatures = self._collect_validator_signatures(genesis)
        genesis.consensus_reached = True
        self.chain.append(genesis)
        print(f"[DLT]  Bloque génesis creado — Hash: {genesis.block_hash[:16]}...")

    def _collect_validator_signatures(self, block: DLTBlock) -> dict[str, str]:
        """
        Simula la recogida de firmas HMAC de cada validador Edge.
        En producción: llamada gRPC a cada nodo con TLS mutuo.
        Cada validador usa una derivación de clave única: HMAC(secret + validator_id).
        """
        signatures = {}
        for vid in self.validator_ids:
            # Clave derivada por validador (simulado; en prod: clave en TPM de cada nodo)
            derived_key = hashlib.sha256(DLT_HMAC_SECRET + vid.encode()).digest()
            sig = hmac.new(derived_key, block.block_hash.encode(), hashlib.sha256).hexdigest()
            signatures[vid] = sig
        return signatures

    def _verify_quorum(self, block: DLTBlock) -> bool:
        """Verifica que ≥ QUORUM_THRESHOLD validadores firmaron el bloque correctamente."""
        valid_count = 0
        for vid, received_sig in block.validator_signatures.items():
            derived_key = hashlib.sha256(DLT_HMAC_SECRET + vid.encode()).digest()
            expected_sig = hmac.new(derived_key, block.block_hash.encode(), hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected_sig, received_sig):
                valid_count += 1
        return valid_count >= QUORUM_THRESHOLD

    def append_block(self, block_type: BlockType, payload: dict) -> DLTBlock:
        """
        Añade un bloque verificado a la cadena.
        Garantías:
          - timestamp_utc > último bloque (monotónico)
          - previous_hash = hash del último bloque
          - quórum de validadores alcanzado
        """
        now_ns = time.time_ns()
        if now_ns <= self._last_timestamp_ns:
            now_ns = self._last_timestamp_ns + 1
        self._last_timestamp_ns = now_ns

        ts = datetime.fromtimestamp(now_ns / 1e9, tz=timezone.utc).isoformat()
        prev_hash = self.chain[-1].block_hash

        block = DLTBlock(
            index=len(self.chain),
            timestamp_utc=ts,
            block_type=block_type.value,
            payload=payload,
            previous_hash=prev_hash,
            nonce=secrets.token_hex(16),
        )
        block.block_hash = block.compute_hash()
        block.hmac_signature = block.sign()
        block.validator_signatures = self._collect_validator_signatures(block)
        block.consensus_reached = self._verify_quorum(block)

        if not block.consensus_reached:
            # En producción: reintentar en banda lateral segura
            print(f"[DLT]   Bloque #{block.index} sin quórum — posible nodo validador caído")

        self.chain.append(block)
        return block

    def verify_chain_integrity(self) -> tuple[bool, list[int]]:
        """
        Verifica toda la cadena DLT de forma completa.
        Retorna (es_válida, lista_de_bloques_corruptos).
        """
        corrupted: list[int] = []
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # 1.Verificar previous_hash
            if current.previous_hash != previous.block_hash:
                corrupted.append(i)
                continue

            # 2.Verificar hash del bloque
            recomputed = current.compute_hash()
            if recomputed != current.block_hash:
                corrupted.append(i)
                continue

            # 3.Verificar HMAC
            expected_hmac = current.sign()
            if not hmac.compare_digest(expected_hmac, current.hmac_signature):
                corrupted.append(i)
                continue

            # 4.Verificar quórum de validadores
            if not self._verify_quorum(current):
                corrupted.append(i)

        is_valid = len(corrupted) == 0
        return is_valid, corrupted

    def get_forensic_export(self) -> dict:
        """Exporta la cadena completa en formato JSON para auditoría forense."""
        is_valid, corrupted = self.verify_chain_integrity()
        return {
            "dlt_export": {
                "truck_id": self.truck_id,
                "export_time": datetime.now(timezone.utc).isoformat(),
                "total_blocks": len(self.chain),
                "chain_valid": is_valid,
                "corrupted_blocks": corrupted,
            },
            "chain": [b.to_dict() for b in self.chain],
        }


# 2. HPE SILICON ROOT OF TRUST

class SiliconRootOfTrust:
    """
    Verificador de integridad de firmware mediante HPE Silicon Root of Trust.

    Basado en la arquitectura real HPE:
      - HPE iLO 6 actúa como raíz de confianza de silicio
      - TPM 2.0 (Trusted Platform Module) almacena valores PCR (Platform Config Registers)
      - Secure Boot UEFI valida la cadena BIOS  Bootloader  OS  App
      - Atestación Remota: el gemelo digital verifica el estado vía iLO REST API

    Cadena de confianza verificada:
      PCR[0]  BIOS/UEFI          hash del firmware de placa base
      PCR[4]  MBR/Bootloader     hash del gestor de arranque
      PCR[8]  OS Kernel          hash del kernel Linux (4.0 hardened)
      PCR[15] Aplicación Ignis   hash del binario fire_truck_twin.py

    Proceso de atestación remota:
      1. iLO genera nonce aleatorio (anti-replay)
      2. TPM firma el Quote (PCRs + nonce) con AIK (Attestation Identity Key)
      3. Gemelo Digital verifica la firma contra el certificado del fabricante HPE
      4. Compara PCRs con los valores baseline (golden measurement)
    """

    # Valores PCR baseline (simulados; en prod: provistos por HPE firmware manifest)
    BASELINE_PCR = {
        0:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # BIOS
        4:  "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # MBR
        8:  "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",  # Kernel
        15: FIRMWARE_BASELINE_HASH,                                               # App Ignis
    }

    def __init__(self, truck_id: str, ilo_endpoint: str = "https://ilo.ignis-001.local"):
        self.truck_id = truck_id
        self.ilo_endpoint = ilo_endpoint
        self.measurements: list[FirmwareMeasurement] = []
        self._last_nonce: str = ""

    def _generate_attestation_nonce(self) -> str:
        """Genera nonce aleatorio para la sesión de atestación (anti-replay)."""
        self._last_nonce = secrets.token_hex(32)
        return self._last_nonce

    def _simulate_tpm_read_pcr(self, pcr_index: int) -> str:
        """
        Simula la lectura del PCR desde el TPM 2.0 vía iLO 6.
        En producción: llamada a iLO REST API con mTLS + JWT.
        GET https://{ilo}/redfish/v1/Systems/1/TrustedModules/TPM/Actions/ReadPCR
        """
        # Simulación: baseline = OK, perturbación aleatoria según el índice
        # En un ataque real de La Sombra, el PCR[15] diferiría del baseline
        baseline = self.BASELINE_PCR.get(pcr_index, "")
        # Simular un sistema no comprometido (mismo hash)
        return baseline

    def _simulate_compromised_tpm_read(self, pcr_index: int) -> str:
        """Simula firmware comprometido (PCR alterado por La Sombra)."""
        # Un atacante que modifica el firmware cambia el PCR
        baseline = self.BASELINE_PCR.get(pcr_index, "")
        if not baseline:
            return ""
        # XOR del último byte para simular alteración
        altered = baseline[:-2] + format(int(baseline[-2:], 16) ^ 0xFF, '02x')
        return altered

    def measure_firmware_component(
        self,
        component: str,
        pcr_index: int,
        simulate_attack: bool = False,
    ) -> FirmwareMeasurement:
        """
        Mide y verifica la integridad de un componente firmware.

        Args:
            component: Nombre del componente ("BIOS", "BOOTLOADER", "OS_KERNEL", "IGNIS_APP")
            pcr_index: Índice del PCR del TPM correspondiente
            simulate_attack: Si True, simula firmware comprometido por La Sombra

        Returns:
            FirmwareMeasurement con resultado de la atestación
        """
        nonce = self._generate_attestation_nonce()
        ts = datetime.now(timezone.utc).isoformat()
        ilo_session = f"ILO6-SESSION-{secrets.token_hex(8).upper()}"

        if simulate_attack:
            measured = self._simulate_compromised_tpm_read(pcr_index)
        else:
            measured = self._simulate_tpm_read_pcr(pcr_index)

        baseline = self.BASELINE_PCR.get(pcr_index, "")
        hashes_match = hmac.compare_digest(measured, baseline)

        if hashes_match:
            trust = TrustLevel.TRUSTED
        elif not measured:
            trust = TrustLevel.UNKNOWN
        else:
            trust = TrustLevel.COMPROMISED

        attestation_report = {
            "nonce": nonce,
            "ilo_endpoint": self.ilo_endpoint,
            "ilo_session_id": ilo_session,
            "pcr_index": pcr_index,
            "pcr_method": "TPM2_Quote_RSAPSS_SHA256",
            "aik_cert_issuer": "HPE Manufacturing CA v3",
            "secure_boot_enabled": True,
            "uefi_db_valid": hashes_match,
            "verdict": trust.value,
        }

        measurement = FirmwareMeasurement(
            component=component,
            measured_hash=measured,
            baseline_hash=baseline,
            trust_level=trust,
            measurement_time=ts,
            ilo_session_id=ilo_session,
            pcr_index=pcr_index,
            attestation_report=attestation_report,
        )
        self.measurements.append(measurement)
        return measurement

    def full_boot_attestation(self, simulate_attack: bool = False) -> dict:
        """
        Ejecuta la cadena completa de atestación de arranque seguro.
        Verifica los 4 componentes en orden (BIOS  App).
        """
        components = [
            ("BIOS_UEFI",    0),
            ("MBR_BOOTLOADER", 4),
            ("OS_KERNEL",    8),
            ("IGNIS_APP",   15),
        ]

        results = []
        overall_trust = TrustLevel.TRUSTED

        print(f"\n[SRoT]  Iniciando atestación HPE Silicon Root of Trust...")
        print(f"[SRoT]    Truck: {self.truck_id} | iLO: {self.ilo_endpoint}")
        print(f"[SRoT]    Protocolo: TPM2_Quote_RSAPSS_SHA256 + Secure Boot UEFI")

        for comp, pcr in components:
            m = self.measure_firmware_component(comp, pcr, simulate_attack)
            results.append(m.to_dict())

            icon = "" if m.is_trusted else ("" if m.trust_level == TrustLevel.COMPROMISED else "")
            print(f"[SRoT]    PCR[{pcr:2d}] {comp:<20} {icon} {m.trust_level.value}")

            if m.trust_level == TrustLevel.COMPROMISED:
                overall_trust = TrustLevel.COMPROMISED
            elif m.trust_level == TrustLevel.UNKNOWN and overall_trust != TrustLevel.COMPROMISED:
                overall_trust = TrustLevel.UNKNOWN

        verdict_icon = " SISTEMA CONFIABLE" if overall_trust == TrustLevel.TRUSTED else \
                       " FIRMWARE COMPROMETIDO — ACTIVAR PROTOCOLO GAMMA" if overall_trust == TrustLevel.COMPROMISED else \
                       "  ESTADO DESCONOCIDO — REQUIERE INSPECCIÓN"
        print(f"[SRoT] {'═'*60}")
        print(f"[SRoT] VEREDICTO FINAL: {verdict_icon}")

        return {
            "truck_id": self.truck_id,
            "attestation_time": datetime.now(timezone.utc).isoformat(),
            "overall_trust_level": overall_trust.value,
            "components_measured": len(results),
            "chain_of_trust": [
                "HPE iLO 6 Silicon Root" ,
                "TPM 2.0 (PCR Anchoring)",
                "UEFI Secure Boot (db/dbx)",
                "OS Kernel (dm-verity)",
                "IGNIS Application (HMAC manifest)",
            ],
            "measurements": results,
        }

    def get_latest_trust_level(self) -> TrustLevel:
        """Retorna el nivel de confianza global de la última atestación."""
        if not self.measurements:
            return TrustLevel.UNKNOWN
        worst = TrustLevel.TRUSTED
        for m in self.measurements:
            if m.trust_level == TrustLevel.COMPROMISED:
                return TrustLevel.COMPROMISED
            if m.trust_level == TrustLevel.UNKNOWN:
                worst = TrustLevel.UNKNOWN
        return worst


# 3. MODO SEGURO CON AUTENTICACIÓN BIOMÉTRICA

class SafeModeProtocol:
    """
    Protocolo de Modo Seguro del Ignis Sentinel.

    Activado cuando el Gemelo Digital detecta ≥ TELEMETRY_CONTRADICTION_THRESHOLD
    contradicciones simultáneas en la telemetría (indicio de inyección por La Sombra).

    Secuencia de activación:
      1. Detección  contradicciones clasificadas por tipo y severidad
      2. Aislamiento  CAN bus crítico desconectado (sistemas autónomos suspendidos)
      3. Alerta  Notificación a mando de bomberos + SOC + HPE GreenLake
      4. Control Manual  Solo se aceptan comandos con token biométrico válido
      5. Reactivación  Reaudiencia DLT + atestación firmware  Modo OPERATIONAL

    Sistemas que se aíslan en Safe Mode:
      - ECU de motor (paso a control directo mecánico)
      - Sistema de dirección asistida electrónica
      - Bomba de agua (control manual por válvulas mecánicas)
      - Comunicaciones externas (WiFi/LTE cortadas, solo 5G privado cifrado)

    Autenticación Biométrica de doble factor:
      - Factor 1: Huella dactilar (sensor capacitivo FPC1321)
      - Factor 2: Iris NIR (Iris ID iCAM 7S)
      - Token vinculado: HMAC(fingerprint_hash + iris_hash + operator_id + timestamp)
      - Validez: 90 segundos desde generación
    """

    def __init__(self, truck_id: str, dlt_blackbox: DigitalBlackBox):
        self.truck_id = truck_id
        self.dlt = dlt_blackbox
        self.current_mode = SystemMode.OPERATIONAL
        self.active_contradictions: list[TelemetryContradiction] = []
        self.safe_mode_events: list[SafeModeEvent] = []
        self.isolated_systems: list[str] = []
        self._safe_mode_start: float = 0.0
        self._prev_telemetry: dict = {}

    # Detección de Contradicciones

    def analyze_telemetry_contradictions(self, telemetry: dict) -> list[TelemetryContradiction]:
        """
        Analiza la telemetría en busca de contradicciones físicas incoherentes.
        Un atacante como La Sombra puede inyectar valores falsos, pero no puede
        violar las leyes físicas simultáneamente en todos los sensores.
        """
        contradictions = []
        ts = datetime.now(timezone.utc).isoformat()

        mech = telemetry.get("mechanical", {})
        hydraulic = telemetry.get("hydraulic", {})
        gps = telemetry.get("gps", {})

        # 1. Combustible vs RPM (modelo físico simplificado)
        if mech:
            rpm = mech.get("engine_rpm", 0)
            speed = mech.get("vehicle_speed_kmh", 0)
            weight = mech.get("gross_weight_kg", 15000)
            reported_consumption = mech.get("fuel_consumption_lph", 0)

            if rpm > 0:
                expected_consumption = 25.0 + (rpm / 3000.0) * 30 + (speed / 100.0) * 15 + (weight / 20000.0) * 10
                error = abs(reported_consumption - expected_consumption) / max(expected_consumption, 1)
                if error > 0.40:  # >40% de desviación del modelo físico
                    contradictions.append(TelemetryContradiction(
                        contradiction_type=ContradictionType.FUEL_PHYSICS_MISMATCH,
                        description=f"Consumo reportado ({reported_consumption:.1f} L/h) incoherente con RPM/velocidad/peso (esperado: {expected_consumption:.1f} L/h)",
                        sensor_a_value=reported_consumption,
                        sensor_b_value=round(expected_consumption, 2),
                        delta_percent=round(error * 100, 1),
                        timestamp=ts,
                        severity=3 if error > 0.70 else 2,
                    ))

        # 2. Velocidad GPS vs Velocidad Mecánica
        if gps and mech:
            gps_speed = gps.get("speed_kmh", 0)
            mech_speed = mech.get("vehicle_speed_kmh", 0)
            if max(gps_speed, mech_speed) > 0:
                speed_delta = abs(gps_speed - mech_speed) / max(gps_speed, mech_speed, 1)
                if speed_delta > 0.20:  # >20% divergencia
                    contradictions.append(TelemetryContradiction(
                        contradiction_type=ContradictionType.GPS_VELOCITY_MISMATCH,
                        description=f"Velocidad GPS ({gps_speed:.1f} km/h) vs Velocímetro ({mech_speed:.1f} km/h) — posible spoofing GPS",
                        sensor_a_value=gps_speed,
                        sensor_b_value=mech_speed,
                        delta_percent=round(speed_delta * 100, 1),
                        timestamp=ts,
                        severity=2 if speed_delta < 0.50 else 3,
                    ))

        # 3. Presión bomba vs Caudal (Ley de Bernoulli simplificada)
        if hydraulic:
            pressure = hydraulic.get("pump_outlet_pressure_kpa", 0)
            flow = hydraulic.get("flow_rate_lpm", 0)
            if pressure > 0 and flow > 0:
                # Q ∝ √P  — relación física bomba centrífuga
                expected_flow_ratio = math.sqrt(pressure / 100.0)  # normalizado
                actual_flow_ratio = flow / 1000.0  # normalizado a 1000 lpm
                ratio_error = abs(expected_flow_ratio - actual_flow_ratio) / max(expected_flow_ratio, 0.1)
                if ratio_error > 0.50:
                    contradictions.append(TelemetryContradiction(
                        contradiction_type=ContradictionType.PRESSURE_FLOW_MISMATCH,
                        description=f"Presión bomba ({pressure:.0f} kPa) incoherente con caudal ({flow:.0f} L/min) — posible manipulación sensor presión",
                        sensor_a_value=pressure,
                        sensor_b_value=flow,
                        delta_percent=round(ratio_error * 100, 1),
                        timestamp=ts,
                        severity=2,
                    ))

        # 4. Comparar con telemetría anterior (saltos anómalos)
        if self._prev_telemetry and mech:
            prev_mech = self._prev_telemetry.get("mechanical", {})
            if prev_mech:
                prev_fuel = prev_mech.get("fuel_level_liters", 0)
                curr_fuel = mech.get("fuel_level_liters", 0)
                # El combustible no puede aumentar sin repostaje
                if curr_fuel > prev_fuel + 5:  # +5L de tolerancia
                    contradictions.append(TelemetryContradiction(
                        contradiction_type=ContradictionType.SEQUENCE_ANOMALY,
                        description=f"Combustible aumentó de {prev_fuel:.0f}L a {curr_fuel:.0f}L sin repostaje — inyección de datos detectada",
                        sensor_a_value=prev_fuel,
                        sensor_b_value=curr_fuel,
                        delta_percent=round((curr_fuel - prev_fuel) / max(prev_fuel, 1) * 100, 1),
                        timestamp=ts,
                        severity=3,
                    ))

        self._prev_telemetry = telemetry
        return contradictions

    def evaluate_safe_mode_trigger(self, contradictions: list[TelemetryContradiction]) -> bool:
        """
        Evalúa si se debe activar el Modo Seguro.
        Criterio: ≥ TELEMETRY_CONTRADICTION_THRESHOLD contradicciones activas,
        o ≥ 1 contradicción de severidad 3 (crítica).
        """
        critical = [c for c in contradictions if c.severity == 3]
        if len(critical) >= 1 or len(contradictions) >= TELEMETRY_CONTRADICTION_THRESHOLD:
            return True
        return False

    # Activación del Modo Seguro

    def activate_safe_mode(self, contradictions: list[TelemetryContradiction]) -> SafeModeEvent:
        """
        Activa el Modo Seguro del Ignis Sentinel.

        Acciones inmediatas (< 500 ms):
          1. Suspender comandos automáticos de CAN Bus
          2. Aislar ECU motor, dirección electrónica, bomba
          3. Cortar comunicaciones WiFi/LTE externas
          4. Notificar jefe de bomberos y SOC
          5. Registrar evento en DLT (inmutable)
        """
        self.current_mode = SystemMode.SAFE_MODE
        self._safe_mode_start = time.time()

        # Sistemas a aislar
        self.isolated_systems = [
            "CAN-ECU-MOTOR",
            "CAN-STEER-ELECTRONIC",
            "CAN-PUMP-CONTROLLER",
            "WIFI-EXTERNAL",
            "LTE-EXTERNAL",
        ]

        event = SafeModeEvent(
            event_type="ACTIVATION",
            trigger_contradictions=[
                {
                    "type": c.contradiction_type.value,
                    "description": c.description,
                    "severity": c.severity,
                    "delta_pct": c.delta_percent,
                }
                for c in contradictions
            ],
            timestamp=datetime.now(timezone.utc).isoformat(),
            isolated_systems=self.isolated_systems.copy(),
        )
        self.safe_mode_events.append(event)

        # Registrar en DLT (inmutable)
        self.dlt.append_block(
            BlockType.SAFE_MODE_EVENT,
            {
                "event": "SAFE_MODE_ACTIVATED",
                "truck_id": self.truck_id,
                "contradictions_count": len(contradictions),
                "isolated_systems": self.isolated_systems,
                "trigger_summary": [c.description for c in contradictions[:3]],
            }
        )

        print(f"\n{'' * 20}")
        print(f"   MODO SEGURO ACTIVADO — Ignis Sentinel {self.truck_id}")
        print(f"  Contradicciones detectadas: {len(contradictions)}")
        for c in contradictions:
            sev_icon = "" if c.severity == 3 else "" if c.severity == 2 else ""
            print(f"  {sev_icon} [{c.contradiction_type.value}] {c.description}")
        print(f"\n   Sistemas aislados:")
        for sys in self.isolated_systems:
            print(f"     · {sys}")
        print(f"\n   ACCIÓN REQUERIDA: Control manual verificado por biometría")
        print(f"   Escanear huella + iris en panel de control del camión")
        print(f"{'' * 20}\n")

        return event

    # Autenticación Biométrica

    def create_biometric_token(
        self,
        operator_id: str,
        fingerprint_raw: bytes,
        iris_raw: bytes,
    ) -> BiometricToken:
        """
        Genera un token biométrico firmado para autenticación en Modo Seguro.

        En producción:
          - fingerprint_raw: plantilla extraída por SDK FPC1321 (minutiae)
          - iris_raw: feature vector extraído por algoritmo IrisCodes (Daugman)
          - Las plantillas NUNCA salen del módulo biométrico en claro;
            solo se expone el hash SHA-256 con salt único

        Args:
            operator_id: ID del operador (ej. "FF-JEFE-BOMBAS-001")
            fingerprint_raw: Bytes de la plantilla de huella
            iris_raw: Bytes del feature vector de iris
        """
        ts = datetime.now(timezone.utc).isoformat()

        # Salt único por sesión (anti-replay de biometría)
        salt = secrets.token_bytes(16)
        fp_hash = hashlib.sha256(salt + fingerprint_raw).hexdigest()
        iris_hash = hashlib.sha256(salt + iris_raw).hexdigest()

        token = BiometricToken(
            operator_id=operator_id,
            fingerprint_hash=fp_hash,
            iris_hash=iris_hash,
            timestamp=ts,
        )
        token.token_hmac = token.compute_token_hmac()
        token.is_valid = True
        return token

    def verify_biometric_and_restore(
        self,
        token: BiometricToken,
        reason: str = "Control manual verificado",
    ) -> bool:
        """
        Verifica el token biométrico y restaura el sistema si es válido.

        Validaciones:
          1. HMAC del token correcto (integridad)
          2. Timestamp dentro de ventana de 90 segundos (frescura)
          3. Modo actual es SAFE_MODE o LOCKDOWN

        Args:
            token: Token biométrico a verificar
            reason: Motivo del restablecimiento (se registra en DLT)

        Returns:
            True si verificación exitosa y sistema restaurado
        """
        if self.current_mode not in (SystemMode.SAFE_MODE, SystemMode.LOCKDOWN):
            print(f"[BioAuth]   Sistema ya en modo {self.current_mode.value}, no se requiere autenticación")
            return True

        # 1. Verificar HMAC
        if not token.verify():
            print(f"[BioAuth]  Token biométrico INVÁLIDO — firma HMAC incorrecta")
            self._register_failed_auth(token, "HMAC_INVALID")
            return False

        # 2. Verificar frescura del token (90 segundos)
        try:
            token_time = datetime.fromisoformat(token.timestamp)
            elapsed = (datetime.now(timezone.utc) - token_time.replace(tzinfo=timezone.utc)).total_seconds()
            if elapsed > 90:
                print(f"[BioAuth]  Token biométrico EXPIRADO ({elapsed:.0f}s > 90s)")
                self._register_failed_auth(token, "TOKEN_EXPIRED")
                return False
        except ValueError:
            print(f"[BioAuth]  Timestamp de token inválido")
            return False

        #  Autenticación exitosa
        print(f"\n[BioAuth]  BIOMETRÍA VERIFICADA")
        print(f"[BioAuth]    Operador: {token.operator_id}")
        print(f"[BioAuth]    Método: {token.auth_method}")
        print(f"[BioAuth]    Motivo: {reason}")

        # Restaurar modo operacional
        prev_mode = self.current_mode
        self.current_mode = SystemMode.OPERATIONAL
        self.isolated_systems = []

        # Registrar en DLT
        self.dlt.append_block(
            BlockType.BIOMETRIC_AUTH,
            {
                "event": "SAFE_MODE_DEACTIVATED",
                "truck_id": self.truck_id,
                "operator_id": token.operator_id,
                "auth_method": token.auth_method,
                "previous_mode": prev_mode.value,
                "reason": reason,
                "systems_restored": ["CAN-ECU-MOTOR", "CAN-STEER-ELECTRONIC",
                                     "CAN-PUMP-CONTROLLER"],
            }
        )

        # Registrar evento
        event = SafeModeEvent(
            event_type="DEACTIVATION",
            trigger_contradictions=[],
            timestamp=datetime.now(timezone.utc).isoformat(),
            biometric_auth={"operator_id": token.operator_id, "method": token.auth_method},
            operator_id=token.operator_id,
        )
        self.safe_mode_events.append(event)

        duration = time.time() - self._safe_mode_start
        print(f"[BioAuth]    Duración Modo Seguro: {duration:.1f}s")
        print(f"[BioAuth]  Sistema restaurado a modo OPERACIONAL\n")

        return True

    def _register_failed_auth(self, token: BiometricToken, reason: str) -> None:
        """Registra intento de autenticación fallido en la DLT."""
        self.dlt.append_block(
            BlockType.BIOMETRIC_AUTH,
            {
                "event": "AUTH_FAILED",
                "truck_id": self.truck_id,
                "operator_id": token.operator_id,
                "failure_reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        # Si hay 3 fallos seguidos, escalar a LOCKDOWN
        failed_auths = sum(
            1 for e in self.safe_mode_events
            if e.event_type == "AUTH_FAILED"
        )
        if failed_auths >= 3:
            self.current_mode = SystemMode.LOCKDOWN
            print(f"[BioAuth]  LOCKDOWN ACTIVADO — 3 intentos biométricos fallidos")


# CLASE ORQUESTADORA: CybersecuritySentinel

class CybersecuritySentinel:
    """
    Orquestador principal de ciberseguridad del Ignis Sentinel.

    Integra los tres módulos:
      1. DigitalBlackBox      Caja Negra DLT (registro inmutable)
      2. SiliconRootOfTrust   Verificación firmware HPE
      3. SafeModeProtocol     Modo Seguro con bio-autenticación

    Punto de entrada: process_secure_telemetry()
    """

    def __init__(self, truck_id: str = "IGNIS-001"):
        self.truck_id = truck_id
        self.dlt = DigitalBlackBox(truck_id)
        self.srot = SiliconRootOfTrust(truck_id)
        self.safe_mode = SafeModeProtocol(truck_id, self.dlt)
        print(f"\n[CybSec]   CybersecuritySentinel INICIADO — {truck_id}")
        print(f"[CybSec]    DLT: {len(self.dlt.chain)} bloques en cadena")
        print(f"[CybSec]    Modo inicial: {self.safe_mode.current_mode.value}\n")

    def process_secure_telemetry(self, telemetry: dict) -> dict:
        """
        Procesa un paquete de telemetría con todos los controles de seguridad.

        Flujo:
          1. Registrar telemetría en DLT (inmutable)
          2. Analizar contradicciones en los datos
          3. Si se detectan ≥ umbral contradicciones  activar Modo Seguro
          4. Retornar estado de seguridad

        Args:
            telemetry: Diccionario de telemetría del camión

        Returns:
            Diccionario con estado de seguridad completo
        """
        # 1. Registrar en DLT (siempre, independientemente del resultado)
        block = self.dlt.append_block(
            BlockType.TELEMETRY,
            {
                "truck_id": self.truck_id,
                "telemetry_hash": hashlib.sha256(
                    json.dumps(telemetry, sort_keys=True).encode()
                ).hexdigest(),
                "mode": self.safe_mode.current_mode.value,
            }
        )

        # 2. Analizar contradicciones
        contradictions = self.safe_mode.analyze_telemetry_contradictions(telemetry)

        # 3. Evaluar disparador de Modo Seguro
        safe_mode_triggered = False
        if contradictions and self.safe_mode.evaluate_safe_mode_trigger(contradictions):
            if self.safe_mode.current_mode == SystemMode.OPERATIONAL:
                self.safe_mode.activate_safe_mode(contradictions)
                safe_mode_triggered = True

        return {
            "truck_id": self.truck_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "system_mode": self.safe_mode.current_mode.value,
            "dlt_block_index": block.index,
            "dlt_block_hash": block.block_hash[:32] + "...",
            "dlt_consensus": block.consensus_reached,
            "contradictions_detected": len(contradictions),
            "contradictions": [
                {
                    "type": c.contradiction_type.value,
                    "severity": c.severity,
                    "delta_pct": c.delta_percent,
                    "description": c.description,
                }
                for c in contradictions
            ],
            "safe_mode_triggered": safe_mode_triggered,
            "isolated_systems": self.safe_mode.isolated_systems,
        }

    def run_firmware_attestation(self, simulate_attack: bool = False) -> dict:
        """Ejecuta atestación completa de firmware y registra resultado en DLT."""
        result = self.srot.full_boot_attestation(simulate_attack)

        # Registrar en DLT
        self.dlt.append_block(
            BlockType.FIRMWARE_CHECK,
            {
                "attestation_result": result["overall_trust_level"],
                "components_measured": result["components_measured"],
                "ilo_endpoint": self.srot.ilo_endpoint,
            }
        )

        if result["overall_trust_level"] == TrustLevel.COMPROMISED.value:
            print(f"[SRoT]  FIRMWARE COMPROMETIDO — Activando Modo Seguro de emergencia")
            emergency_contradiction = TelemetryContradiction(
                contradiction_type=ContradictionType.SEQUENCE_ANOMALY,
                description="Firmware comprometido detectado por HPE Silicon Root of Trust",
                sensor_a_value="PCR_MEDIDO",
                sensor_b_value="PCR_BASELINE",
                delta_percent=100.0,
                timestamp=datetime.now(timezone.utc).isoformat(),
                severity=3,
            )
            self.safe_mode.activate_safe_mode([emergency_contradiction])

        return result

    def get_security_summary(self) -> dict:
        """Retorna resumen completo del estado de seguridad."""
        chain_valid, corrupted = self.dlt.verify_chain_integrity()
        return {
            "truck_id": self.truck_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "system_mode": self.safe_mode.current_mode.value,
            "dlt": {
                "total_blocks": len(self.dlt.chain),
                "chain_integrity": "VALID" if chain_valid else f"CORRUPTED (bloques: {corrupted})",
                "validators": self.dlt.validator_ids,
                "quorum_threshold": f"{QUORUM_THRESHOLD}/{QUORUM_VALIDATORS}",
            },
            "firmware": {
                "trust_level": self.srot.get_latest_trust_level().value,
                "measurements_count": len(self.srot.measurements),
                "ilo_endpoint": self.srot.ilo_endpoint,
            },
            "safe_mode": {
                "events_total": len(self.safe_mode.safe_mode_events),
                "isolated_systems": self.safe_mode.isolated_systems,
                "active_contradictions": len(self.safe_mode.active_contradictions),
            },
        }


# DEMO: Escenarios de Ataque de La Sombra

def run_demo():
    """
    Demostración completa del módulo de ciberseguridad con tres escenarios:
      A. Telemetría normal (sin ataque)
      B. Ataque La Sombra: inyección de telemetría contradictoria
      C. Ataque La Sombra: firmware comprometido + recuperación biométrica
    """
    print("\n" + "═"*70)
    print("IGNIS SENTINEL — Módulo de Ciberseguridad Industrial ")
    print("═"*70 + "\n")

    sentinel = CybersecuritySentinel("IGNIS-001")

    # ESCENARIO A: Telemetría Normal
    print("\n" + "─"*60)
    print("ESCENARIO A — Telemetría Normal (sin ataque)")
    print("─"*60)

    normal_telemetry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mechanical": {
            "engine_rpm": 2500,
            "vehicle_speed_kmh": 60,
            "gross_weight_kg": 18000,
            "fuel_level_liters": 450,
            "fuel_consumption_lph": 65.0,  # Coherente con modelo físico
        },
        "hydraulic": {
            "pump_outlet_pressure_kpa": 800,
            "flow_rate_lpm": 1200,
        },
        "gps": {"speed_kmh": 60},
    }

    result_A = sentinel.process_secure_telemetry(normal_telemetry)
    print(f"   Modo: {result_A['system_mode']}")
    print(f"   DLT Bloque #{result_A['dlt_block_index']} — Hash: {result_A['dlt_block_hash']}")
    print(f"   Contradicciones: {result_A['contradictions_detected']}")

    # ESCENARIO B: Ataque La Sombra
    print("\n" + "─"*60)
    print("ESCENARIO B — La Sombra inyecta telemetría contradictoria")
    print("─"*60)

    # La Sombra inyecta datos falsos: combustible aumenta (imposible sin repostaje),
    # velocidad GPS difiere del velocímetro, y consumo no cuadra con RPM
    attack_telemetry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mechanical": {
            "engine_rpm": 800,          # RPM muy bajas
            "vehicle_speed_kmh": 90,    # Velocímetro dice 90
            "gross_weight_kg": 18000,
            "fuel_level_liters": 490,   #  IMPOSIBLE: subió 40L desde escenario A
            "fuel_consumption_lph": 12.0,  #  12 L/h con 800 RPM y 90 km/h  incoherente
        },
        "hydraulic": {
            "pump_outlet_pressure_kpa": 1500,  # Presión muy alta
            "flow_rate_lpm": 50,               # Pero caudal mínimo  violación Bernoulli
        },
        "gps": {"speed_kmh": 20},  #  GPS dice 20 km/h, mecánica dice 90
    }

    result_B = sentinel.process_secure_telemetry(attack_telemetry)
    print(f"\n   Modo resultante: {result_B['system_mode']}")
    print(f"   Sistemas aislados: {len(result_B['isolated_systems'])}")

    # RECUPERACIÓN BIOMÉTRICA
    if result_B['system_mode'] == SystemMode.SAFE_MODE.value:
        print("\n" + "─"*60)
        print("RECUPERACIÓN — Autenticación Biométrica del Jefe de Bombas")
        print("─"*60)

        # Simular datos biométricos del operador autorizado
        fake_fingerprint = hashlib.sha256(b"OPERADOR_JUAN_GARCIA_HUELLA_RAW").digest()
        fake_iris = hashlib.sha256(b"OPERADOR_JUAN_GARCIA_IRIS_RAW").digest()

        token = sentinel.safe_mode.create_biometric_token(
            operator_id="FF-JEFE-BOMBAS-JG001",
            fingerprint_raw=fake_fingerprint,
            iris_raw=fake_iris,
        )
        success = sentinel.safe_mode.verify_biometric_and_restore(
            token,
            reason="Verificación manual in situ — situación controlada"
        )
        print(f"  Resultado autenticación: {' ACCESO CONCEDIDO' if success else ' DENEGADO'}")

    # ESCENARIO C: Firmware Comprometido
    print("\n" + "─"*60)
    print("ESCENARIO C — La Sombra modifica firmware en arranque")
    print("─"*60)

    sentinel2 = CybersecuritySentinel("IGNIS-002")
    attestation = sentinel2.run_firmware_attestation(simulate_attack=True)
    print(f"\n  Veredicto firmware: {attestation['overall_trust_level']}")

    # ESTADO FINAL Y EXPORTACIÓN DLT
    print("\n" + "═"*70)
    print("RESUMEN DE SEGURIDAD — Ignis Sentinel IGNIS-001")
    print("═"*70)
    summary = sentinel.get_security_summary()
    print(json.dumps(summary, indent=2, ensure_ascii=False))

    print("\nVerificación integridad DLT IGNIS-001:")
    valid, corrupted = sentinel.dlt.verify_chain_integrity()
    print(f"Cadena: {' ÍNTEGRA' if valid else f' BLOQUES CORRUPTOS: {corrupted}'}")
    print(f"Total bloques: {len(sentinel.dlt.chain)}")
    print(f"Quórum: {QUORUM_THRESHOLD}/{QUORUM_VALIDATORS} validadores Edge\n")


if __name__ == "__main__":
    run_demo()
