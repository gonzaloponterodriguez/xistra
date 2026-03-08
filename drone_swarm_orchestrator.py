"""
Módulo de Orquestación de Enjambre de Drones

  1. DroneFleetController  — Máquina de estados + orquestación K3s (simulada)
  2. ThermalHeatmap3D      — Fusión Bayesiana de 4 señales FLIR  mapa 3D vivo
  3. CannonPressureAI      — IA: firma humana en zona bloqueada  presión de cañones

"""

from __future__ import annotations

import json
import math
import time
import random
import hashlib
import dataclasses
from enum import Enum, auto
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field


# CONSTANTES GLOBALES

VOXEL_SIZE_M       = 0.5      # metros por celda del grid 3D
GRID_X             = 200      # celdas en X (100 m)
GRID_Y             = 200      # celdas en Y (100 m)
GRID_Z             = 40       # celdas en Z (20 m)
TEMP_BLOCKED_C     = 350.0    # °C — umbral para declarar zona bloqueada
TEMP_EXTINCTION_C  = 300.0    # °C — temperatura a la que el agua extingue
ETA_WATER          = 0.65     # eficiencia del agua nebulizada
RHO_WATER          = 998.0    # kg/m³ a 20°C
CD_NOZZLE          = 0.82     # coeficiente de descarga boquilla
A_NOZZLE_M2        = 0.002    # área boquilla (50 mm Ø ≈ 0.002 m²)
CP_AIR_KJ          = 1.005    # kJ/(kg·K) calor específico aire combustible
HUMAN_CONF_THRESH  = 0.72     # umbral de confianza YOLOv8
TEMPORAL_DECAY_L   = 0.10     # λ para decaimiento exponencial de confianza
CANNON_P_MIN       = 8.0      # bar mínimo de operación
CANNON_P_MAX       = 40.0     # bar máximo software (limitador mecánico a 42)
WATER_RESERVE_L    = 500.0    # litros de reserva de seguridad


#1. ORQUESTACIÓN DE DRONES (DroneFleetController)

class DronePhase(Enum):
    GROUNDED   = auto()
    LAUNCHING  = auto()
    PATROLLING = auto()
    HOVERING   = auto()   # posición fija sobre hotspot humano
    RTB        = auto()   # Return To Base
    CHARGING   = auto()
    FAILSAFE   = auto()


class DroneSector(Enum):
    NORTE = "NORTE"
    SUR   = "SUR"
    ESTE  = "ESTE"
    OESTE = "OESTE"


@dataclass
class DroneState:
    drone_id:     str
    sector:       DroneSector
    phase:        DronePhase       = DronePhase.GROUNDED
    battery_pct:  int              = 100
    altitude_m:   float            = 0.0
    position_m:   Tuple[float,float,float] = (0.0, 0.0, 0.0)  # (x, y, z)
    last_ping_ms: int              = 0
    thermal_fps:  float            = 30.0
    ip_address:   str              = "10.0.1.10"
    mission_time_s: float          = 0.0
    _launch_t:    float            = field(default=0.0, repr=False)

    def is_operational(self) -> bool:
        return self.phase not in (DronePhase.FAILSAFE, DronePhase.CHARGING, DronePhase.GROUNDED)

    def to_k8s_crd(self) -> dict:
        """Simula el estado del CRD Kubernetes del dron."""
        return {
            "apiVersion": "ignis.sentinel.io/v1",
            "kind": "Drone",
            "metadata": {"name": self.drone_id, "namespace": "ignis-swarm"},
            "spec": {
                "droneId":    self.drone_id,
                "sector":     self.sector.value,
                "altitude_m": round(self.altitude_m, 1),
                "battery_pct": self.battery_pct,
                "ip_address": self.ip_address,
            },
            "status": {
                "phase":        self.phase.name,
                "last_ping_ms": self.last_ping_ms,
                "thermal_fps":  self.thermal_fps,
            }
        }


class DroneFleetController:
    """
    Orquestador de enjambre de 4 drones (simula el pod 'drone-controller' en K3s).

    Responsabilidades:
      - Gestionar la máquina de estados de cada dron (MAVLink 2.0 simulado)
      - Detectar fallos y redistribuir cobertura
      - Exponer la API de misión: launch_all(), update_tick(), status_report()
    """

    CRUISE_ALTITUDE_M = 50.0    # altitud de patrulla estándar
    LAUNCH_DURATION_S = 45.0    # tiempo de ascenso hasta altitud de crucero
    RTB_BATTERY_PCT   = 15      # % batería para iniciar retorno

    # Waypoints de patrulla en lemniscata (figura 8) — coordenadas relativas al camión (m)
    _LEMNISCATE: Dict[DroneSector, List[Tuple[float,float]]] = {
        DroneSector.NORTE: [(-20,50),(0,60),(20,50),(30,40),(20,30),(0,40),(-20,30)],
        DroneSector.SUR:   [(-20,-50),(0,-60),(20,-50),(30,-40),(20,-30),(0,-40),(-20,-30)],
        DroneSector.ESTE:  [(50,-20),(60,0),(50,20),(40,30),(30,20),(40,0),(30,-20)],
        DroneSector.OESTE: [(-50,-20),(-60,0),(-50,20),(-40,30),(-30,20),(-40,0),(-30,-20)],
    }

    def __init__(self, truck_id: str = "IGNIS-001"):
        self.truck_id = truck_id
        self._ts      = time.time()       # reloj interno (simulado)
        self.drones: List[DroneState] = [
            DroneState("D1", DroneSector.NORTE, ip_address="10.0.1.11"),
            DroneState("D2", DroneSector.SUR,   ip_address="10.0.1.12"),
            DroneState("D3", DroneSector.ESTE,  ip_address="10.0.1.13"),
            DroneState("D4", DroneSector.OESTE, ip_address="10.0.1.14"),
        ]
        self._wp_idx: Dict[str, int] = {d.drone_id: 0 for d in self.drones}
        self._events: List[dict] = []

    # Ciclo de vida

    def launch_all(self) -> List[str]:
        """Ordena el despegue de todos los drones en tierra. Retorna lista de IDs lanzados."""
        launched = []
        for d in self.drones:
            if d.phase == DronePhase.GROUNDED:
                d.phase     = DronePhase.LAUNCHING
                d._launch_t = self._ts
                launched.append(d.drone_id)
                self._emit_event(d.drone_id, "LAUNCH_ORDERED",
                                 f"Dron {d.drone_id} iniciando despegue hacia {self.CRUISE_ALTITUDE_M}m")
        return launched

    def update_tick(self, dt_seconds: float = 1.0) -> List[dict]:
        """
        Avanza el estado de todos los drones dt_seconds hacia el futuro.
        Simula: ascenso, patrulla en lemniscata, consumo de batería, fallos.
        Retorna lista de eventos generados en este tick.
        """
        self._ts += dt_seconds
        self._events.clear()

        for d in self.drones:
            d.mission_time_s += dt_seconds

            if d.phase == DronePhase.LAUNCHING:
                self._tick_launching(d, dt_seconds)
            elif d.phase == DronePhase.PATROLLING:
                self._tick_patrolling(d, dt_seconds)
            elif d.phase == DronePhase.HOVERING:
                self._tick_hovering(d, dt_seconds)
            elif d.phase == DronePhase.RTB:
                self._tick_rtb(d, dt_seconds)
            elif d.phase == DronePhase.CHARGING:
                self._tick_charging(d, dt_seconds)

            # Simular latido MAVLink HEARTBEAT
            d.last_ping_ms = int((time.time() % 1) * 1000)

        # Redistribuir cobertura si hay drones fuera
        self._rebalance_coverage()
        return list(self._events)

    def _tick_launching(self, d: DroneState, dt: float):
        elapsed = self._ts - d._launch_t
        progress = min(elapsed / self.LAUNCH_DURATION_S, 1.0)
        d.altitude_m  = progress * self.CRUISE_ALTITUDE_M
        d.battery_pct = max(0, d.battery_pct - int(dt * 0.08))  # 0.08%/s en ascenso
        if progress >= 1.0:
            d.phase    = DronePhase.PATROLLING
            d.altitude_m = self.CRUISE_ALTITUDE_M
            self._emit_event(d.drone_id, "PATROL_START",
                             f"Dron {d.drone_id} en altitud, iniciando patrulla {d.sector.value}")

    def _tick_patrolling(self, d: DroneState, dt: float):
        waypoints = self._LEMNISCATE[d.sector]
        idx       = self._wp_idx[d.drone_id]
        wp        = waypoints[idx]
        d.position_m = (wp[0], wp[1], self.CRUISE_ALTITUDE_M)
        # Avanzar waypoint cada 5 s
        if int(d.mission_time_s) % 5 == 0:
            self._wp_idx[d.drone_id] = (idx + 1) % len(waypoints)
        d.battery_pct = max(0, d.battery_pct - int(dt * 0.028))  # ~55 min de vuelo
        if d.battery_pct <= self.RTB_BATTERY_PCT:
            d.phase = DronePhase.RTB
            self._emit_event(d.drone_id, "RTB_INITIATED",
                             f"Dron {d.drone_id} batería baja ({d.battery_pct}%), regresando")

    def _tick_hovering(self, d: DroneState, dt: float):
        d.battery_pct = max(0, d.battery_pct - int(dt * 0.025))
        if d.battery_pct <= self.RTB_BATTERY_PCT:
            d.phase = DronePhase.RTB

    def _tick_rtb(self, d: DroneState, dt: float):
        d.altitude_m  = max(0.0, d.altitude_m - dt * (self.CRUISE_ALTITUDE_M / 30.0))
        d.battery_pct = max(0, d.battery_pct - int(dt * 0.05))
        if d.altitude_m <= 0.5:
            d.altitude_m  = 0.0
            d.phase       = DronePhase.CHARGING
            self._emit_event(d.drone_id, "LANDED",
                             f"Dron {d.drone_id} en plataforma FATO, iniciando carga")

    def _tick_charging(self, d: DroneState, dt: float):
        # 35 min para carga completa: ~2.86%/min  0.048%/s
        d.battery_pct = min(100, d.battery_pct + int(dt * 0.048 * 60))
        if d.battery_pct >= 95:
            d.phase    = DronePhase.GROUNDED
            self._emit_event(d.drone_id, "READY",
                             f"Dron {d.drone_id} cargado ({d.battery_pct}%), listo para misión")

    def _rebalance_coverage(self):
        """Si ≤2 drones operativos, emite alerta de cobertura reducida."""
        ops = sum(1 for d in self.drones if d.is_operational())
        if ops <= 2:
            self._emit_event("FLEET", "COVERAGE_DEGRADED",
                             f"Solo {ops}/4 drones operativos — sectores ampliados a 90°")

    def failsafe_drone(self, drone_id: str, reason: str = "K8s LivenessProbe timeout"):
        """Declara un dron en FAILSAFE (simula fallo de pod en K3s)."""
        for d in self.drones:
            if d.drone_id == drone_id:
                d.phase = DronePhase.FAILSAFE
                self._emit_event(drone_id, "FAILSAFE",
                                 f"Dron {drone_id} en FAILSAFE: {reason}")

    def hover_over_human(self, drone_id: str, position_m: Tuple[float,float,float]):
        """Ordena a un dron que se fije sobre una firma humana detectada."""
        for d in self.drones:
            if d.drone_id == drone_id:
                d.phase      = DronePhase.HOVERING
                d.position_m = position_m
                self._emit_event(drone_id, "HOVER_ORDERED",
                                 f"Dron {drone_id} fijado sobre firma humana en {position_m}")

    def _emit_event(self, source: str, event_type: str, message: str):
        self._events.append({
            "timestamp_us": int(self._ts * 1e6),
            "source":       source,
            "type":         event_type,
            "message":      message,
        })

    def status_report(self) -> dict:
        """Genera informe de estado estilo kubectl get drones."""
        ops = [d for d in self.drones if d.is_operational()]
        return {
            "truck_id":        self.truck_id,
            "timestamp_us":    int(self._ts * 1e6),
            "operational":     len(ops),
            "total":           len(self.drones),
            "coverage_pct":    round(len(ops) / len(self.drones) * 100, 1),
            "drones": [d.to_k8s_crd() for d in self.drones],
        }


# 2. MAPA DE CALOR 3D VIVO (ThermalHeatmap3D)

@dataclass
class ThermalVoxel:
    x_m:               float
    y_m:               float
    z_m:               float
    temperature_c:     float   = 20.0
    confidence:        float   = 0.0
    last_update_ts:    float   = 0.0
    human_probability: float   = 0.0
    blocked:           bool    = False

    def update(self, new_temp: float, weight: float, ts: float):
        """Actualización Bayesiana de temperatura con peso de contribución."""
        if self.confidence == 0:
            self.temperature_c = new_temp
            self.confidence    = weight
        else:
            total_w            = self.confidence + weight
            self.temperature_c = (self.confidence * self.temperature_c + weight * new_temp) / total_w
            self.confidence    = min(1.0, total_w)
        self.last_update_ts = ts
        self.blocked        = self.temperature_c > TEMP_BLOCKED_C


@dataclass
class DroneFrame:
    """Frame térmico recibido de un dron (simula resultado del stream-ingress pod)."""
    drone_id:    str
    sector:      DroneSector
    timestamp_us: int
    gps_lat:     float
    gps_lon:     float
    altitude_m:  float
    # Lista de observaciones: (x_m, y_m, z_m, temperatura_c, angulo_incidencia_deg)
    observations: List[Tuple[float,float,float,float,float]] = field(default_factory=list)


class ThermalHeatmap3D:
    """
    Motor de fusión Bayesiana de 4 señales FLIR.
    Simula el pod 'heatmap-fusion' ejecutándose en GPU en el clúster K3s.

    Modelo matemático:
      T_fused = Σ(wᵢ·Tᵢ) / Σ(wᵢ)
      wᵢ = confidence_i × angle_penalty_i × temporal_decay_i
      angle_penalty  = max(0, cos(θ))
      temporal_decay = exp(-λ·Δt)
    """

    def __init__(self):
        # Grid 3D de voxels —inicializado en temperatura ambiente
        self._grid: Dict[Tuple[int,int,int], ThermalVoxel] = {}
        self._ts   = time.time()
        self._frame_count = 0
        self._fusion_latency_ms_history: List[float] = []

    # API pública

    def ingest_frame(self, frame: DroneFrame) -> int:
        """
        Procesa un frame de un dron y actualiza el grid 3D.
        Retorna número de voxels actualizados.
        """
        t_start = time.time()
        self._ts = frame.timestamp_us / 1e6
        updated  = 0

        for (x, y, z, temp, theta_deg) in frame.observations:
            key = self._world_to_voxel(x, y, z)
            if not self._in_bounds(key):
                continue

            # Calcular peso de contribución
            dt            = self._ts - self._grid.get(key, ThermalVoxel(x,y,z)).last_update_ts
            angle_pen     = max(0.0, math.cos(math.radians(theta_deg)))
            temp_decay    = math.exp(-TEMPORAL_DECAY_L * dt)
            weight        = angle_pen * temp_decay

            if key not in self._grid:
                cx, cy, cz = self._voxel_center(key)
                self._grid[key] = ThermalVoxel(cx, cy, cz, last_update_ts=self._ts)

            self._grid[key].update(temp, weight, self._ts)
            updated += 1

        self._frame_count += 1
        latency_ms = (time.time() - t_start) * 1000
        self._fusion_latency_ms_history.append(latency_ms)
        return updated

    def get_hotspots(self, min_temp_c: float = 200.0) -> List[ThermalVoxel]:
        """Retorna todos los voxels sobre un umbral, ordenados por temperatura desc."""
        return sorted(
            [v for v in self._grid.values() if v.temperature_c >= min_temp_c and v.confidence > 0.3],
            key=lambda v: v.temperature_c,
            reverse=True
        )

    def get_blocked_zones(self) -> List[ThermalVoxel]:
        """Voxels con fuego activo (T > 350°C)."""
        return [v for v in self._grid.values() if v.blocked]

    def get_human_signatures(self) -> List[ThermalVoxel]:
        """Voxels con firma humana detectada (probabilidad > umbral)."""
        return [v for v in self._grid.values() if v.human_probability > HUMAN_CONF_THRESH]

    def inject_human_signature(self, x_m: float, y_m: float, z_m: float, probability: float):
        """
        Inyecta la salida del detector YOLOv8 en el voxel correspondiente.
        En producción real, el pod human-signature-detector escribe en Redis.
        """
        key = self._world_to_voxel(x_m, y_m, z_m)
        if key in self._grid:
            self._grid[key].human_probability = probability
        else:
            cx, cy, cz = self._voxel_center(key)
            v = ThermalVoxel(cx, cy, cz, last_update_ts=self._ts, human_probability=probability)
            self._grid[key] = v

    def export_mqtt_payload(self) -> dict:
        """
        Genera el payload protobuf-equivalente para publicar en:
        Topic MQTT: ignis/swarm/heatmap3d (cadencia: 500 ms)
        """
        hotspots   = self.get_hotspots(min_temp_c=100.0)
        humans     = self.get_human_signatures()
        blocked    = self.get_blocked_zones()
        max_temp   = max((v.temperature_c for v in hotspots), default=20.0)

        return {
            "timestamp_us":    int(self._ts * 1e6),
            "frame_count":     self._frame_count,
            "voxel_count":     len(hotspots),
            "max_temp_c":      round(max_temp, 1),
            "blocked_count":   len(blocked),
            "human_signatures": [
                {
                    "x_m": round(h.x_m, 2), "y_m": round(h.y_m, 2), "z_m": round(h.z_m, 2),
                    "probability": round(h.human_probability, 3),
                    "blocked_adjacent": any(
                        b for b in blocked
                        if abs(b.x_m - h.x_m) < 2.0 and abs(b.y_m - h.y_m) < 2.0
                    ),
                }
                for h in humans
            ],
            "avg_fusion_latency_ms": round(
                sum(self._fusion_latency_ms_history[-10:]) / max(1, len(self._fusion_latency_ms_history[-10:])), 2
            ),
        }

    def summary_stats(self) -> dict:
        """Estadísticas del mapa para el gemelo digital."""
        all_temps = [v.temperature_c for v in self._grid.values() if v.confidence > 0.1]
        return {
            "active_voxels":    len(self._grid),
            "blocked_voxels":   len(self.get_blocked_zones()),
            "human_detections": len(self.get_human_signatures()),
            "max_temp_c":       round(max(all_temps, default=20.0), 1),
            "avg_temp_c":       round(sum(all_temps) / max(1, len(all_temps)), 1),
            "frames_processed": self._frame_count,
        }

    # Helpers privados

    @staticmethod
    def _world_to_voxel(x: float, y: float, z: float) -> Tuple[int,int,int]:
        return (
            int(x / VOXEL_SIZE_M) + GRID_X // 2,
            int(y / VOXEL_SIZE_M) + GRID_Y // 2,
            int(z / VOXEL_SIZE_M),
        )

    @staticmethod
    def _voxel_center(key: Tuple[int,int,int]) -> Tuple[float,float,float]:
        ix, iy, iz = key
        return (
            (ix - GRID_X//2) * VOXEL_SIZE_M + VOXEL_SIZE_M / 2,
            (iy - GRID_Y//2) * VOXEL_SIZE_M + VOXEL_SIZE_M / 2,
            iz * VOXEL_SIZE_M + VOXEL_SIZE_M / 2,
        )

    @staticmethod
    def _in_bounds(key: Tuple[int,int,int]) -> bool:
        ix, iy, iz = key
        return 0 <= ix < GRID_X and 0 <= iy < GRID_Y and 0 <= iz < GRID_Z


# 3. IA DE RECÁLCULO DE PRESIÓN (CannonPressureAI)

@dataclass
class CannonCommand:
    cannon_id:        str
    pressure_bar:     float
    azimuth_deg:      float
    elevation_deg:    float

    def __str__(self):
        return (f"[{self.cannon_id}] {self.pressure_bar:.1f} bar | "
                f"Az={self.azimuth_deg:.1f}° El={self.elevation_deg:.1f}°")


@dataclass
class RescueCorridorResult:
    """Resultado del algoritmo AbrirCorredor()."""
    trigger:               str
    human_position_m:      Tuple[float,float,float]
    human_probability:     float
    blocking_voxels_count: int
    cannon_commands:       List[CannonCommand]
    estimated_opening_time_s: float
    water_required_liters: float
    water_available_liters: float
    alert:                 Optional[str]

    def to_mqtt_payload(self) -> dict:
        return {
            "timestamp_us":     int(time.time() * 1e6),
            "trigger":          self.trigger,
            "human_position_m": {"x": self.human_position_m[0],
                                  "y": self.human_position_m[1],
                                  "z": self.human_position_m[2]},
            "human_probability":       round(self.human_probability, 3),
            "blocking_voxels_count":   self.blocking_voxels_count,
            "cannon_commands": [
                {
                    "cannon_id":     c.cannon_id,
                    "pressure_bar":  round(c.pressure_bar, 1),
                    "azimuth_deg":   round(c.azimuth_deg, 1),
                    "elevation_deg": round(c.elevation_deg, 1),
                }
                for c in self.cannon_commands
            ],
            "estimated_opening_time_s": round(self.estimated_opening_time_s, 1),
            "water_required_liters":    round(self.water_required_liters, 0),
            "water_available_liters":   round(self.water_available_liters, 0),
            "alert": self.alert,
        }


CANNONS = [
    {"id": "FRONT_LEFT",  "az_base": 315.0, "el_base": 10.0},
    {"id": "FRONT_RIGHT", "az_base": 45.0,  "el_base": 10.0},
    {"id": "ROOF_TURRET", "az_base": 0.0,   "el_base": 55.0},
]


class CannonPressureAI:
    """
    Detecta firma humana en zona bloqueada y recalcula la presión
    necesaria en los cañones de agua para 'abrir camino' (AbrirCorredor).

    Simula el pod 'cannon-pressure-controller' del clúster K3s.
    El modelo de presión se basa en:
        Q_needed = m_fuel × Cp × ΔT / η_water
        P_cannon = Q_needed / (Cd × A × √(2ρ))
    """

    def __init__(self,
                 water_available_liters: float = 8000.0,
                 detector_hash: str = ""):
        self.water_available = water_available_liters
        # Hash del modelo YOLOv8 (inmutable — validado desde K8s ConfigMap)
        self._detector_hash = detector_hash or hashlib.sha256(b"yolov8_thermal_ignis_v1").hexdigest()
        self._compromised   = False
        self._history: List[RescueCorridorResult] = []

    def validate_detector_integrity(self, runtime_hash: str) -> bool:
        """
        Verifica que el modelo YOLOv8 no haya sido alterado.
        Si falla  modo MANUAL_OVERRIDE requerido.
        """
        ok = hmac_compare(self._detector_hash, runtime_hash)
        if not ok:
            self._compromised = True
        return ok

    def check_and_act(self,
                      heatmap: ThermalHeatmap3D,
                      water_available_liters: float) -> Optional[RescueCorridorResult]:
        """
        Punto de entrada principal. Llama a AbrirCorredor() si detecta
        una firma humana válida en zona bloqueada.

        Retorna None si no hay firma humana o el detector está comprometido.
        """
        if self._compromised:
            return None  # Seguridad: sin actuación autónoma si modelo adulterado

        # Buscar firma humana adyacente a zona bloqueada
        humans  = heatmap.get_human_signatures()
        blocked = heatmap.get_blocked_zones()

        target = None
        for h in humans:
            for b in blocked:
                dist = math.sqrt((h.x_m-b.x_m)**2 + (h.y_m-b.y_m)**2 + (h.z_m-b.z_m)**2)
                if dist < 3.0:   # dentro de 3 m de fuego activo
                    target = h
                    break
            if target:
                break

        if target is None:
            return None

        return self._abrir_corredor(
            human=target,
            blocked_zones=blocked,
            water_available=water_available_liters,
        )

    def _abrir_corredor(self,
                        human: ThermalVoxel,
                        blocked_zones: List[ThermalVoxel],
                        water_available: float) -> RescueCorridorResult:
        """
        Algoritmo AbrirCorredor():
        1. Traza rayo virtual cañón  posición humana
        2. Identifica obstáculos de fuego en el rayo
        3. Calcula caudal y presión necesarios para extinguirlos
        4. Emite comandos a cañones priorizando el ángulo más directo
        """
        human_pos = (human.x_m, human.y_m, human.z_m)

        # Paso 1-2: identificar voxels bloqueados en el corredor al humano
        corridor_blocked = self._raycast_blocked(human_pos, blocked_zones)

        # Paso 3: calcular energía necesaria
        Q_total_kJ  = self._compute_thermal_energy(corridor_blocked)
        W_needed_L  = self._energy_to_water_liters(Q_total_kJ)

        # Paso 4: calcular presión por cañón
        bearing_az  = math.degrees(math.atan2(human.x_m, human.y_m)) % 360
        elevation   = math.degrees(math.atan2(human.z_m, max(0.1, math.hypot(human.x_m, human.y_m))))

        commands: List[CannonCommand] = []
        for c in CANNONS:
            # Girar turret hacia el objetivo (add ±15° fan spread para cobertura)
            az = (bearing_az + (15 if "RIGHT" in c["id"] else -15 if "LEFT" in c["id"] else 0)) % 360
            el = min(85.0, max(0.0, elevation + (20 if "ROOF" in c["id"] else 0)))
            # Presión proporcional a energía, limitada al rango operativo
            p  = self._compute_pressure(Q_total_kJ / len(CANNONS))
            commands.append(CannonCommand(cannon_id=c["id"], pressure_bar=p, azimuth_deg=az, elevation_deg=el))

        # Paso 5: comprobar autonomía
        t_open_s = self._estimate_opening_time(W_needed_L, commands)
        alert: Optional[str] = None
        if water_available - W_needed_L < WATER_RESERVE_L:
            alert = "APOYO_NECESARIO — reserva de agua crítica"

        result = RescueCorridorResult(
            trigger               = "HUMAN_IN_BLOCKED_ZONE",
            human_position_m      = human_pos,
            human_probability     = human.human_probability,
            blocking_voxels_count = len(corridor_blocked),
            cannon_commands       = commands,
            estimated_opening_time_s = t_open_s,
            water_required_liters = W_needed_L,
            water_available_liters= water_available,
            alert                 = alert,
        )
        self._history.append(result)
        return result

    # Métodos de física

    @staticmethod
    def _raycast_blocked(target: Tuple[float,float,float],
                         blocked: List[ThermalVoxel]) -> List[ThermalVoxel]:
        """
        Filtra los voxels bloqueados que se interponen entre (0,0,0) (cañones del camión)
        y el objetivo, usando distancia al segmento de línea.
        """
        ox, oy, oz = 0.0, 0.0, 1.5   # origen: nivel cañón del camión
        tx, ty, tz = target
        segment_len = math.sqrt((tx-ox)**2 + (ty-oy)**2 + (tz-oz)**2)

        in_path = []
        for v in blocked:
            vx, vy, vz = v.x_m, v.y_m, v.z_m
            # Distancia perpendicular al rayo (proyección)
            t = ((vx-ox)*(tx-ox) + (vy-oy)*(ty-oy) + (vz-oz)*(tz-oz)) / max(1e-6, segment_len**2)
            t = max(0.0, min(1.0, t))
            px = ox + t*(tx-ox); py = oy + t*(ty-oy); pz = oz + t*(tz-oz)
            dist_perp = math.sqrt((vx-px)**2 + (vy-py)**2 + (vz-pz)**2)
            if dist_perp < 1.5:    # dentro de 1.5 m del rayo  obstáculo
                in_path.append(v)
        return in_path

    @staticmethod
    def _compute_thermal_energy(voxels: List[ThermalVoxel]) -> float:
        """
        Calcula la energía térmica a absorber (kJ) para extinguir todos los voxels.
        Q = m_air × Cp × ΔT / η_water, modelando masa de aire caliente en cada voxel.
        """
        total_kJ = 0.0
        for v in voxels:
            delta_t  = max(0, v.temperature_c - TEMP_EXTINCTION_C)
            vol_m3   = VOXEL_SIZE_M ** 3
            # Densidad del aire caliente (aprox.): ρ_caliente = 1.2 × (293 / (273 + T))
            rho_hot  = 1.2 * (293 / max(1, 273 + v.temperature_c))
            m_kg     = rho_hot * vol_m3
            q_kJ     = (m_kg * CP_AIR_KJ * delta_t) / ETA_WATER
            total_kJ += q_kJ
        return max(0.1, total_kJ)

    @staticmethod
    def _energy_to_water_liters(Q_kJ: float) -> float:
        """
        Litros de agua para absorber Q kJ.
        L = Q / (m_water × Cp_water(4.186 kJ/kg·K) × ΔT_agua(~75°C) + Lv_evap(2257 kJ/kg))
        Aproximación simplificada: L ≈ Q / 2500 (kJ/L de agua nebulizada)
        """
        kJ_per_liter = 2500.0  # agua nebulizada + evaporación
        liters        = Q_kJ / kJ_per_liter
        return max(10.0, liters * 1000 / 1.0)   # convert to liters (ρ_water≈1 kg/L)

    @staticmethod
    def _compute_pressure(Q_partial_kJ: float) -> float:
        """
        P = Q / (Cd × A × √(2ρ)) — simplificado a escala [bar].
        Mapeo lineal: 0–500 kJ  8–40 bar.
        """
        p_linear = 8.0 + (Q_partial_kJ / 500.0) * (CANNON_P_MAX - CANNON_P_MIN)
        return round(max(CANNON_P_MIN, min(CANNON_P_MAX, p_linear)), 1)

    @staticmethod
    def _estimate_opening_time(water_L: float, commands: List[CannonCommand]) -> float:
        """
        Tiempo estimado de apertura del corredor.
        Caudal total Q_L/s ≈ Σ Cd × A × √(2ρ × P) / 1000
        """
        flow_rate_ls = sum(
            CD_NOZZLE * A_NOZZLE_M2 * math.sqrt(2 * RHO_WATER * c.pressure_bar * 1e5) / 1000
            for c in commands
        )
        return water_L / max(0.1, flow_rate_ls)

    def get_history(self) -> List[dict]:
        return [r.to_mqtt_payload() for r in self._history]


# HELPERS

def hmac_compare(a: str, b: str) -> bool:
    """Comparación de tiempo constante de dos hashes (anti-timing attack)."""
    if len(a) != len(b):
        return False
    result = 0
    for ca, cb in zip(a, b):
        result |= ord(ca) ^ ord(cb)
    return result == 0


def generate_synthetic_drone_frame(
        drone_id: str,
        sector: DroneSector,
        fire_center_m: Tuple[float, float] = (30.0, 30.0),
        fire_radius_m: float = 10.0,
        fire_temp_c: float = 700.0,
        n_observations: int = 120,
        seed: Optional[int] = None,
) -> DroneFrame:
    """
    Genera un frame FLIR sintético para testing/demo.
    Simula el resultado del geo-registro y proyección perspectiva del stream-ingress pod.
    """
    rng = random.Random(seed)
    obs = []
    for _ in range(n_observations):
        # Muestra aleatoria en el área vigilada por el sector
        if sector == DroneSector.NORTE:
            x = rng.uniform(-25, 25); y = rng.uniform(25, 65)
        elif sector == DroneSector.SUR:
            x = rng.uniform(-25, 25); y = rng.uniform(-65, -25)
        elif sector == DroneSector.ESTE:
            x = rng.uniform(25, 65);  y = rng.uniform(-25, 25)
        else:
            x = rng.uniform(-65, -25); y = rng.uniform(-25, 25)
        z = rng.uniform(0.5, 12.0)   # altura en edificio

        # Temperatura: gaussiana centrada en el fuego
        dist_to_fire = math.sqrt((x - fire_center_m[0])**2 + (y - fire_center_m[1])**2)
        if dist_to_fire < fire_radius_m:
            temp = fire_temp_c * math.exp(-(dist_to_fire**2) / (2*(fire_radius_m/2)**2))
            temp += rng.gauss(0, 20)
        else:
            temp = rng.gauss(28, 5)   # temperatura ambiente + humo

        angle = rng.uniform(0, 60)    # ángulo de incidencia de la cámara
        obs.append((x, y, z, max(15.0, temp), angle))

    return DroneFrame(
        drone_id     = drone_id,
        sector       = sector,
        timestamp_us = int(time.time() * 1e6),
        gps_lat      = 43.3623 + rng.gauss(0, 0.0003),
        gps_lon      = -8.4115 + rng.gauss(0, 0.0003),
        altitude_m   = 50.0,
        observations = obs,
    )


# DEMOSTRACIÓN PRINCIPAL

def run_demo():
    """
    Demo completa del sistema de enjambre:
      1. Lanza los 4 drones y simula 3 ticks de misión
      2. Los 4 drones capturan frames térmicos de un incendio real
      3. El mapa 3D fusiona las 4 señales Bayesianamente
      4. Un civil es detectado en zona bloqueada
      5. La IA recalcula presión de cañones y genera el comando MQTT
    """
    print("\nIGNIS SENTINEL -ENJAMBRE DE DRONES")
    print("Orquestación K3s - Fusión 3D - IA Presión Cañones \n")

    # 1. ORQUESTACIÓN K3s
    print("\n1. K3s DroneFleetController — Inicializando clúster...")
    fleet = DroneFleetController(truck_id="IGNIS-001")
    launched = fleet.launch_all()
    print(f"   Drones lanzados: {launched}")

    for tick in range(1, 4):
        events = fleet.update_tick(dt_seconds=16.0)    # 16s por tick = 48s total
        if events:
            for ev in events:
                icon = {"LAUNCH_ORDERED":"","PATROL_START":"","RTB_INITIATED":"",
                        "LANDED":"","READY":"","FAILSAFE":"","HOVER_ORDERED":"",
                        "COVERAGE_DEGRADED":""}.get(ev["type"],"")
                print(f"  {icon} Tick {tick} | {ev['source']:10s} | {ev['type']:25s} | {ev['message']}")

    report = fleet.status_report()
    print(f"\n   Estado flota: {report['operational']}/{report['total']} drones | "
          f"Cobertura: {report['coverage_pct']}%")
    for d in report["drones"]:
        st = d["status"]
        sp = d["spec"]
        print(f"      {sp['droneId']} [{sp['sector']:5s}] "
              f"Fase={st['phase']:10s} Batería={sp['battery_pct']}% Alt={sp['altitude_m']}m")

    # 2. FUSIÓN 3D
    print("\n2. ThermalHeatmap3D - Fusión Bayesiana 4 señales FLIR")
    heatmap = ThermalHeatmap3D()

    fire_center  = (30.0, 30.0)
    drone_configs = [
        ("D1", DroneSector.NORTE, 680.0),
        ("D2", DroneSector.SUR,   720.0),
        ("D3", DroneSector.ESTE,  650.0),
        ("D4", DroneSector.OESTE, 700.0),
    ]

    for drone_id, sector, fire_temp in drone_configs:
        frame = generate_synthetic_drone_frame(
            drone_id=drone_id, sector=sector,
            fire_center_m=fire_center, fire_temp_c=fire_temp,
            n_observations=150, seed=hash(drone_id) % 999
        )
        updated = heatmap.ingest_frame(frame)
        print(f"   Frame ingesta {drone_id} [{sector.value:5s}]: {updated} voxels actualizados")

    stats = heatmap.summary_stats()
    print(f"\n   Estadísticas del mapa 3D:")
    print(f"Voxels activos:   {stats['active_voxels']}")
    print(f"Zonas bloqueadas: {stats['blocked_voxels']} (T > {TEMP_BLOCKED_C}°C)")
    print(f"Temperatura max:  {stats['max_temp_c']}°C")
    print(f"Temperatura media:{stats['avg_temp_c']}°C")

    # Top 3 hotspots
    hotspots = heatmap.get_hotspots(min_temp_c=300.0)[:3]
    print(f"\n   Top-3 hotspots:")
    for i, h in enumerate(hotspots, 1):
        print(f"     #{i} ({h.x_m:.1f}, {h.y_m:.1f}, {h.z_m:.1f})m  "
              f"{h.temperature_c:.0f}°C | conf={h.confidence:.2f} | blocked={h.blocked}")

    # 3. IA: FIRMA HUMANA  PRESIÓN CAÑONES
    print("\n3. CannonPressureAI - Detección firma humana + AbrirCorredor()")

    # Inyectar firma humana en el mapa (simula salida de YOLOv8)
    human_x, human_y, human_z = 28.5, 29.0, 3.8    # adyacente al foco del incendio
    heatmap.inject_human_signature(human_x, human_y, human_z, probability=0.91)
    print(f"Firma humana detectada (YOLOv8) en ({human_x}, {human_y}, {human_z})m | "
          f"confianza=91%")

    ai = CannonPressureAI(water_available_liters=5340.0)
    result = ai.check_and_act(heatmap, water_available_liters=5340.0)

    if result:
        print(f"\nEVENTO: {result.trigger}")
        print(f"Voxels bloqueados en corredor: {result.blocking_voxels_count}")
        print(f"Agua necesaria:  {result.water_required_liters:.0f} L")
        print(f"Agua disponible: {result.water_available_liters:.0f} L")
        print(f"Tiempo apertura: {result.estimated_opening_time_s:.0f} s")
        if result.alert:
            print(f"ALERTA: {result.alert}")
        print(f"\nComandos de cañones:")
        for c in result.cannon_commands:
            print(f"{c}")

        # Serializar payload MQTT
        payload = result.to_mqtt_payload()
        print(f"\nPayload MQTT  ignis/actuators/cannon/set")
        print("  " + json.dumps(payload, indent=4, ensure_ascii=False).replace("\n", "\n  "))
    else:
        print("Sin firma humana en zona bloqueada. Sistema en espera.")

    # MQTT Heatmap
    hm_payload = heatmap.export_mqtt_payload()
    print("[MQTT]  ignis/swarm/heatmap3d (último payload):")
    print("  " + json.dumps(hm_payload, indent=4, ensure_ascii=False).replace("\n", "\n  "))

    print("Demo completada. Sistema en modo de guardia continua.")


if __name__ == "__main__":
    run_demo()
