"""
Módulo RA Proyectiva

Puente de Realidad Aumentada Proyectiva entre el Gemelo Digital del
camión Ignis Sentinel y los cascos AR de los bomberos.

Implementa:
  - BIMModel: representación simplificada de planos BIM en Python
  - ThermalFusionEngine: fusión térmica FLIR + LiDAR  mapa 3D
  - EscapeRoutePlanner: A* sobre grafo de nodos BIM con bloqueo térmico
  - ARHelmetBridge: motor principal que genera el ARHelmetFrame
  - Escenario 'La Sombra': simulación de oscuridad + humo opaco
"""

from __future__ import annotations

import heapq
import json
import math
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, List, Tuple



# CONSTANTES DEL MÓDULO AR
AR_LATENCY_TARGET_MS   = 80.0   # ms — latencia máxima extremo a extremo
EDGE_PIPELINE_MS       = 17.5   # ms — pipeline HPE Edgeline (GPU+FPGA)
HOTSPOT_THRESHOLD_C    = 250.0  # °C — temperatura mínima para hotspot
ROUTE_BLOCKED_TEMP_C   = 60.0   # °C — temperatura que bloquea un nodo de ruta
ASTAR_REFRESH_MS       = 200    # ms — frecuencia de recálculo de ruta A*
FLASHOVER_THRESHOLD_C  = 530.0  # °C — temperatura aproximada de flashover


# ENUMERACIONES
class ThermalZone(Enum):
    """Clasificación táctica de zona según temperatura."""
    SAFE        = "SEGURA"          # < 40 °C
    WARM        = "TEMPLADA"        # 40–100 °C
    HOT         = "CALIENTE"        # 100–250 °C
    DANGER      = "PELIGROSA"       # 250–500 °C
    LETHAL      = "MORTAL"          # > 500 °C
    COLLAPSE    = "COLAPSO"         # Predicción modelo estructural


class AlertTypeAR(Enum):
    """Tipos de alerta específicos del módulo AR."""
    FLASHOVER_RISK      = "RIESGO_FLASHOVER"
    STRUCTURAL_COLLAPSE = "COLAPSO_ESTRUCTURAL"
    SHADOW_TRAP         = "TRAMPA_LA_SOMBRA"
    VISIBILITY_ZERO     = "VISIBILIDAD_NULA"
    FIREFIGHTER_DOWN    = "BOMBERO_CAIDO"
    EXIT_BLOCKED        = "SALIDA_BLOQUEADA"


class FallbackMode(Enum):
    """Modo de conectividad activo entre camión y cascos."""
    PRIMARY   = "5G_SA_MMWAVE"     # 5G SA mmWave < 5 ms
    SECONDARY = "WIFI6E"           # WiFi 6E < 15 ms
    TERTIARY  = "UWB"              # UWB — solo posición + alertas
    AUTONOMOUS = "LOCAL_CASCO"     # Modo autónomo casco, máx. 30 s


# DATACLASSES
@dataclass
class BIMNode:
    """Nodo del grafo BIM (habitación, pasillo, tramo de escalera, salida)."""
    node_id: str
    name: str
    floor: int
    position_xyz: tuple[float, float, float]   # coordenadas métricas
    is_exit: bool = False
    is_exit_blocked: bool = False
    connected_to: List[str] = field(default_factory=list)  # IDs vecinos
    current_temp_celsius: float = 22.0
    structural_risk: float = 0.0   # 0.0 = ninguno · 1.0 = colapso inminente


@dataclass
class BIMModel:
    """
    Modelo BIM simplificado de un edificio.
    En producción se cargaría desde un fichero IFC 2×3 o un servidor BCA.
    """
    building_id: str
    building_name: str
    address: str
    floors: int
    nodes: Dict[str, BIMNode] = field(default_factory=dict)

    def add_node(self, node: BIMNode) -> None:
        self.nodes[node.node_id] = node

    def get_exits(self) -> List[BIMNode]:
        return [n for n in self.nodes.values() if n.is_exit and not n.is_exit_blocked]

    def apply_thermal_data(self, thermal_map: Dict[str, float]) -> None:
        """Aplica un mapa {node_id: temp_celsius} al modelo BIM."""
        for node_id, temp in thermal_map.items():
            if node_id in self.nodes:
                self.nodes[node_id].current_temp_celsius = temp


@dataclass
class ThermalPoint3D:
    """Punto tridimensional con temperatura asignada."""
    x: float
    y: float
    z: float
    celsius: float

    @property
    def zone(self) -> ThermalZone:
        if self.celsius < 40:
            return ThermalZone.SAFE
        if self.celsius < 100:
            return ThermalZone.WARM
        if self.celsius < 250:
            return ThermalZone.HOT
        if self.celsius < 500:
            return ThermalZone.DANGER
        return ThermalZone.LETHAL


@dataclass
class EscapeRoute:
    """Ruta de escape calculada por el planificador A*."""
    route_id: str
    waypoints: List[str]          # IDs de nodos BIM
    waypoints_3d: List[Tuple]     # posiciones XYZ en metros
    estimated_seconds: float
    safety_score: float           # 1.0 = totalmente segura
    exit_node_id: str


@dataclass
class FirefighterStatus:
    """Estado de un bombero dentro del edificio."""
    ff_id: str
    position_node_id: str
    pos_3d: tuple[float, float, float]
    heart_rate_bpm: int
    spo2_percent: int
    is_down: bool = False


@dataclass
class ARAlert:
    """Alerta embebida en el frame AR."""
    alert_type: AlertTypeAR
    node_id: str
    description: str
    probability: float
    eta_seconds: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "alert_type": self.alert_type.value,
            "node_id": self.node_id,
            "description": self.description,
            "probability": self.probability,
            "eta_seconds": self.eta_seconds,
        }


@dataclass
class ARHelmetFrame:
    """
    Payload completo enviado al casco AR en cada ciclo de renderizado.
    Transmitido vía 5G SA (QCI-1 URLLC) como SRTP/DTLS 1.3 sobre H.265.
    """
    frame_id: str
    timestamp_utc: str
    building_id: str
    latency_budget_ms: float
    fallback_mode: FallbackMode
    thermal_hotspots: List[ThermalPoint3D]
    escape_routes: List[EscapeRoute]
    active_alerts: List[ARAlert]
    firefighter_status: List[FirefighterStatus]
    visibility_optical: bool          # True = visibilidad óptica > 0
    xray_vision_active: bool          # True = modo rayos X activado
    shadow_trap_detected: bool        # True = trampa La Sombra detectada

    def to_dict(self) -> dict:
        d = {
            "frame_id": self.frame_id,
            "timestamp_utc": self.timestamp_utc,
            "building_id": self.building_id,
            "latency_budget_ms": self.latency_budget_ms,
            "fallback_mode": self.fallback_mode.value,
            "xray_vision_active": self.xray_vision_active,
            "visibility_optical": self.visibility_optical,
            "shadow_trap_detected": self.shadow_trap_detected,
            "thermal_hotspots": [
                {
                    "xyz": [h.x, h.y, h.z],
                    "celsius": h.celsius,
                    "zone": h.zone.value,
                }
                for h in self.thermal_hotspots
            ],
            "escape_routes": [
                {
                    "route_id": r.route_id,
                    "waypoints": r.waypoints,
                    "waypoints_3d": r.waypoints_3d,
                    "estimated_seconds": round(r.estimated_seconds, 1),
                    "safety_score": round(r.safety_score, 2),
                    "exit": r.exit_node_id,
                }
                for r in self.escape_routes
            ],
            "active_alerts": [a.to_dict() for a in self.active_alerts],
            "firefighters": [
                {
                    "id": ff.ff_id,
                    "node": ff.position_node_id,
                    "pos_3d": list(ff.pos_3d),
                    "vitals": {
                        "hr_bpm": ff.heart_rate_bpm,
                        "spo2_pct": ff.spo2_percent,
                    },
                    "is_down": ff.is_down,
                }
                for ff in self.firefighter_status
            ],
        }
        return d


# MOTOR DE FUSIÓN TÉRMICA

class ThermalFusionEngine:
    """
    Simula el motor de fusión FLIR + LiDAR que corre en la GPU RTX A5000
    del HPE Edgeline EL8000.

    En producción:
      - LiDAR (Velodyne VLP-32C) provee la nube de puntos 3D.
      - FLIR (Teledyne 640×512, 14-bit) provee temperatura por pixel.
      - El FPGA Intel Agilex 7 registra ambas fuentes mediante ICP.
      - La GPU proyecta temperatura en la malla BIM.
    """

    def __init__(self, resolution_hz: int = 20):
        self.resolution_hz = resolution_hz   # frecuencia de actualización
        self._pipeline_start_ns = 0

    def start_pipeline(self) -> None:
        self._pipeline_start_ns = time.perf_counter_ns()

    def pipeline_elapsed_ms(self) -> float:
        return (time.perf_counter_ns() - self._pipeline_start_ns) / 1_000_000

    def fuse_thermal_to_bim(
        self,
        bim: BIMModel,
        raw_thermal_map: Dict[str, float],
    ) -> List[ThermalPoint3D]:
        """
        Aplica el mapa térmico al modelo BIM y retorna los hotspots 3D.

        Args:
            bim: Modelo BIM del edificio con nodos posicionados.
            raw_thermal_map: {node_id: temperatura_celsius} del sensor FLIR.

        Returns:
            Lista de ThermalPoint3D ordenados por temperatura descendente.
        """
        bim.apply_thermal_data(raw_thermal_map)
        hotspots: List[ThermalPoint3D] = []

        for node in bim.nodes.values():
            pt = ThermalPoint3D(
                x=node.position_xyz[0],
                y=node.position_xyz[1],
                z=node.position_xyz[2],
                celsius=node.current_temp_celsius,
            )
            if pt.celsius >= HOTSPOT_THRESHOLD_C:
                hotspots.append(pt)

        return sorted(hotspots, key=lambda p: p.celsius, reverse=True)

    def estimate_flashover_risk(self, node: BIMNode) -> float:
        """
        Devuelve probabilidad de flashover (0.0–1.0) para un nodo BIM.
        Modelo simplificado: sigmoide centrada en FLASHOVER_THRESHOLD_C.
        """
        delta = node.current_temp_celsius - FLASHOVER_THRESHOLD_C
        return 1 / (1 + math.exp(-delta / 50))


# PLANIFICADOR DE RUTAS DE ESCAPE (A*)

class EscapeRoutePlanner:
    """
    Calcula rutas de escape óptimas mediante el algoritmo A* sobre el grafo BIM.

    Los nodos cuya temperatura supere ROUTE_BLOCKED_TEMP_C quedan bloqueados.
    El heurístico es la distancia euclídea a la salida más cercana.
    """

    def __init__(self, walk_speed_ms: float = 1.2):
        self.walk_speed_ms = walk_speed_ms  # velocidad media con EPI (m/s)

    def _euclidean(self, a: BIMNode, b: BIMNode) -> float:
        ax, ay, az = a.position_xyz
        bx, by, bz = b.position_xyz
        return math.sqrt((ax-bx)**2 + (ay-by)**2 + (az-bz)**2)

    def is_passable(self, node: BIMNode) -> bool:
        """Nodo accesible si está bajo umbral de temperatura y sin colapso."""
        return (
            node.current_temp_celsius < ROUTE_BLOCKED_TEMP_C
            and node.structural_risk < 0.9
        )

    def compute_safety_score(self, path: List[BIMNode]) -> float:
        """
        Calcula la puntuación de seguridad de la ruta (1.0 = totalmente segura).
        Penaliza temperatura alta y riesgo estructural.
        """
        if not path:
            return 0.0
        penalties = []
        for node in path:
            temp_penalty = min(node.current_temp_celsius / 300.0, 1.0)
            struct_penalty = node.structural_risk
            penalties.append(max(temp_penalty, struct_penalty))
        return round(1.0 - max(penalties), 2)

    def find_route(
        self,
        bim: BIMModel,
        start_node_id: str,
        exit_node_id: str,
        route_id: str = "R-01",
    ) -> Optional[EscapeRoute]:
        """
        Ejecuta A* desde start_node_id hasta exit_node_id.

        Returns:
            EscapeRoute si existe camino seguro, None si está bloqueado.
        """
        if start_node_id not in bim.nodes or exit_node_id not in bim.nodes:
            return None

        goal = bim.nodes[exit_node_id]
        open_set: List[Tuple[float, str]] = []
        heapq.heappush(open_set, (0.0, start_node_id))

        came_from: Dict[str, Optional[str]] = {start_node_id: None}
        g_score: Dict[str, float] = {start_node_id: 0.0}

        while open_set:
            _, current_id = heapq.heappop(open_set)
            if current_id == exit_node_id:
                # Reconstruir camino
                path_ids: list[str] = []
                node_id: Optional[str] = exit_node_id
                while node_id is not None:
                    path_ids.append(node_id)
                    node_id = came_from[node_id]
                path_ids.reverse()

                path_nodes = [bim.nodes[nid] for nid in path_ids]
                total_dist = sum(
                    self._euclidean(path_nodes[i], path_nodes[i+1])
                    for i in range(len(path_nodes)-1)
                )
                est_seconds = total_dist / self.walk_speed_ms
                safety = self.compute_safety_score(path_nodes)

                return EscapeRoute(
                    route_id=route_id,
                    waypoints=path_ids,
                    waypoints_3d=[n.position_xyz for n in path_nodes],
                    estimated_seconds=est_seconds,
                    safety_score=safety,
                    exit_node_id=exit_node_id,
                )

            current = bim.nodes[current_id]
            for neighbor_id in current.connected_to:
                if neighbor_id not in bim.nodes:
                    continue
                neighbor = bim.nodes[neighbor_id]
                if not self.is_passable(neighbor):
                    continue

                tentative_g = g_score[current_id] + self._euclidean(current, neighbor)
                if tentative_g < g_score.get(neighbor_id, float('inf')):
                    came_from[neighbor_id] = current_id
                    g_score[neighbor_id] = tentative_g
                    h = self._euclidean(neighbor, goal)
                    heapq.heappush(open_set, (tentative_g + h, neighbor_id))

        return None  # Sin camino seguro disponible

    def find_all_routes(
        self,
        bim: BIMModel,
        start_node_id: str,
    ) -> List[EscapeRoute]:
        """Calcula una ruta a cada salida disponible del edificio."""
        routes = []
        for i, exit_node in enumerate(bim.get_exits()):
            route = self.find_route(
                bim, start_node_id, exit_node.node_id, route_id=f"R-{i+1:02d}"
            )
            if route:
                routes.append(route)
        # Ordenar por puntuación de seguridad descendente
        return sorted(routes, key=lambda r: r.safety_score, reverse=True)


# MOTOR PRINCIPAL: ARHelmetBridge

class ARHelmetBridge:
    """
    Motor principal del Módulo RA Proyectiva del Ignis Sentinel.

    Orquesta la fusión de datos BIM, térmica, rutas de escape y alertas
    del Gemelo Digital para generar el ARHelmetFrame enviado a los cascos.

    Flujo:
        Gemelo Digital (FireTruckTwin)  ARHelmetBridge  5G privada  Casco AR

    Simula el pipeline que correría en el HPE Edgeline EL8000 con:
        - GPU NVIDIA RTX A5000: fusión térmica y renderizado
        - FPGA Intel Agilex 7: compresión H.265 < 2 ms
        - 5G UPF local (Nokia AEQD): transmisión < 1 ms
    """

    def __init__(
        self,
        truck_id: str = "IGNIS-001",
        bim_model: Optional[BIMModel] = None,
    ):
        self.truck_id       = truck_id
        self.bim            = bim_model
        self.fusion_engine  = ThermalFusionEngine()
        self.route_planner  = EscapeRoutePlanner()
        self._frame_counter = 0
        self._fallback_mode = FallbackMode.PRIMARY
        self._last_frame_ms = 0.0

        print(f"[{truck_id}]  ARHelmetBridge INICIADO")
        print(f"[{truck_id}]    Latencia objetivo: < {AR_LATENCY_TARGET_MS} ms E2E")
        print(f"[{truck_id}]    Pipeline Edgeline: ~{EDGE_PIPELINE_MS} ms GPU+FPGA\n")

    # MÉTODO PRINCIPAL

    def generate_ar_frame(
        self,
        thermal_map: Dict[str, float],
        firefighters: List[FirefighterStatus],
        twin_alerts: List[dict],
        optical_visibility: bool = True,
        shadow_attack_active: bool = False,
        start_node_id: str = "ENTRADA",
    ) -> ARHelmetFrame:
        """
        Genera el ARHelmetFrame para transmisión a los cascos.

        Args:
            thermal_map: Mapa {node_id: °C} del sensor FLIR actualizado.
            firefighters: Lista de estados de bomberos con posición 3D.
            twin_alerts: Alertas del FireTruckTwin (dicts TwinAlert.to_dict()).
            optical_visibility: False si humo/oscuridad bloquean cámaras ópticas.
            shadow_attack_active: True si se detecta ataque de La Sombra.
            start_node_id: Nodo BIM de referencia para calcular rutas.

        Returns:
            ARHelmetFrame listo para serialización y transmisión 5G.
        """
        if not self.bim:
            raise ValueError("BIMModel no cargado. Usa load_bim() primero.")

        self._frame_counter += 1
        self.fusion_engine.start_pipeline()

        frame_id = f"{self.truck_id}:AR:{self._frame_counter:06d}"
        ts       = datetime.now(timezone.utc).isoformat()

        # PASO 1: Fusión térmica en GPU
        hotspots = self.fusion_engine.fuse_thermal_to_bim(self.bim, thermal_map)

        # PASO 2: Construcción de alertas AR
        ar_alerts: list[ARAlert] = []

        # Flashover por nodos calientes
        for node in self.bim.nodes.values():
            fo_risk = self.fusion_engine.estimate_flashover_risk(node)
            if fo_risk > 0.7:
                ar_alerts.append(ARAlert(
                    alert_type=AlertTypeAR.FLASHOVER_RISK,
                    node_id=node.node_id,
                    description=f"Riesgo de flashover en {node.name} ({node.current_temp_celsius:.0f}°C)",
                    probability=round(fo_risk, 2),
                    eta_seconds=max(5, (1.0 - fo_risk) * 120),
                ))

            # Colapso estructural
            if node.structural_risk > 0.6:
                ar_alerts.append(ARAlert(
                    alert_type=AlertTypeAR.STRUCTURAL_COLLAPSE,
                    node_id=node.node_id,
                    description=f"Riesgo colapso estructural en {node.name}",
                    probability=round(node.structural_risk, 2),
                    eta_seconds=max(10, (1.0 - node.structural_risk) * 90),
                ))

        # Trampa La Sombra: salidas bloqueadas artificialmente
        shadow_trap = False
        for node in self.bim.nodes.values():
            if node.is_exit and node.is_exit_blocked:
                # Chequear si la temperatura real NO justifica el bloqueo
                if node.current_temp_celsius < ROUTE_BLOCKED_TEMP_C and shadow_attack_active:
                    shadow_trap = True
                    ar_alerts.append(ARAlert(
                        alert_type=AlertTypeAR.SHADOW_TRAP,
                        node_id=node.node_id,
                        description=(
                            f" TRAMPA LA SOMBRA detectada: {node.name} "
                            f"marcada bloqueada SIN justificación térmica "
                            f"(T={node.current_temp_celsius:.0f}°C)"
                        ),
                        probability=0.97,
                    ))

        # Visibilidad óptica nula (humo/oscuridad)
        xray_active = not optical_visibility
        if not optical_visibility:
            ar_alerts.append(ARAlert(
                alert_type=AlertTypeAR.VISIBILITY_ZERO,
                node_id="GLOBAL",
                description="Visibilidad óptica NULA — Modo Visión Rayos X activado (FLIR+Radar SAR)",
                probability=1.0,
            ))

        # Bomberos caídos
        for ff in firefighters:
            if ff.is_down:
                ar_alerts.append(ARAlert(
                    alert_type=AlertTypeAR.FIREFIGHTER_DOWN,
                    node_id=ff.position_node_id,
                    description=f" BOMBERO {ff.ff_id} CAÍDO — SpO₂={ff.spo2_percent}% · FC={ff.heart_rate_bpm}",
                    probability=1.0,
                ))

        # PASO 3: Rutas de escape A*
        routes = self.route_planner.find_all_routes(self.bim, start_node_id)

        # PASO 4: Medir latencia del pipeline
        pipeline_ms = self.fusion_engine.pipeline_elapsed_ms()
        self._last_frame_ms = pipeline_ms

        # PASO 5: Ensamblar ARHelmetFrame
        return ARHelmetFrame(
            frame_id=frame_id,
            timestamp_utc=ts,
            building_id=self.bim.building_id,
            latency_budget_ms=pipeline_ms,
            fallback_mode=self._fallback_mode,
            thermal_hotspots=hotspots,
            escape_routes=routes,
            active_alerts=ar_alerts,
            firefighter_status=firefighters,
            visibility_optical=optical_visibility,
            xray_vision_active=xray_active,
            shadow_trap_detected=shadow_trap,
        )

    def load_bim(self, bim: BIMModel) -> None:
        """Carga o actualiza el modelo BIM del edificio."""
        self.bim = bim
        print(f"[{self.truck_id}]  BIM cargado: {bim.building_name} ({bim.building_id})")

    def set_fallback_mode(self, mode: FallbackMode) -> None:
        """Cambia el modo de conectividad activo (degradación por ataque)."""
        self._fallback_mode = mode
        print(f"[{self.truck_id}]  Modo conectividad  {mode.value}")

    def print_frame_summary(self, frame: ARHelmetFrame) -> None:
        """Imprime un resumen legible del frame AR en consola táctica."""
        sep = "═" * 72
        print(f"\n{sep}")
        print(f"AR FRAME | {frame.frame_id}")
        print(f"Red: {frame.fallback_mode.value} | Pipeline: {frame.latency_budget_ms:.2f} ms")
        print(f"Edificio: {frame.building_id}")
        print(f"Visión: {'ÓPTICA' if frame.visibility_optical else ' NULA  RAYOS X ACTIVO'}")
        if frame.shadow_trap_detected:
            print(f"TRAMPA LA SOMBRA DETECTADA")
        print(f"\nHotspots ({len(frame.thermal_hotspots)}):")
        for hp in frame.thermal_hotspots[:5]:
            print(f"[{hp.zone.value}] {hp.celsius:.0f}°C @ ({hp.x:.1f}, {hp.y:.1f}, {hp.z:.1f})")
        print(f"\nRutas de escape ({len(frame.escape_routes)}):")
        for r in frame.escape_routes:
            bar = "█" * int(r.safety_score * 10)
            print(f"{r.route_id}: {r.exit_node_id} | {r.estimated_seconds:.0f}s | "
                  f"Seguridad: {bar} {r.safety_score:.0%}")
        print(f"\nAlertas AR ({len(frame.active_alerts)}):")
        for a in frame.active_alerts:
            print(f"[{a.alert_type.value}] {a.description} (P={a.probability:.0%})")
        print(f"\nBomberos en edificio ({len(frame.firefighter_status)}):")
        for ff in frame.firefighter_status:
            estado = "CAÍDO" if ff.is_down else "OPERATIVO"
            print(f"{ff.ff_id}: {estado} | FC={ff.heart_rate_bpm} bpm | SpO₂={ff.spo2_percent}%")
        print(f"{sep}\n")


# FÁBRICA: Edificio de demostración

def build_demo_bim() -> BIMModel:
    """
    Construye un modelo BIM simplificado de un edificio de 3 plantas para demo.
    Representa el edificio del Escenario 'Sombra Negra'.
    """
    bim = BIMModel(
        building_id="BIM:CORUÑA:EDIFICIO-7",
        building_name="Edificio Industrial Polígono Norte — Nave 7",
        address="Polígono Norte, A Coruña",
        floors=3,
    )

    # Planta 0 (Baja)
    nodos_p0 = [
        BIMNode("ENTRADA",    "Vestíbulo Entrada",   0, (0.0, 0.0, 0.0),   connected_to=["P0-PASILLO-A", "P0-ALMACEN-1"]),
        BIMNode("P0-PASILLO-A","Pasillo Planta Baja", 0, (5.0, 0.0, 0.0),   connected_to=["ENTRADA", "P0-SALA-MAQUINAS", "P0-ESCALERA-SUR", "EXIT-NORTE"]),
        BIMNode("P0-ALMACEN-1","Almacén 1",           0, (3.0, -4.0, 0.0),  connected_to=["ENTRADA"]),
        BIMNode("P0-SALA-MAQUINAS","Sala Máquinas",   0, (10.0, 0.0, 0.0),  connected_to=["P0-PASILLO-A"]),
        BIMNode("P0-ESCALERA-SUR","Escalera Sur P0",  0, (5.0, 6.0, 0.0),   connected_to=["P0-PASILLO-A", "P1-ESCALERA-SUR"]),
        BIMNode("EXIT-NORTE", "Salida Norte",          0, (8.0, -3.0, 0.0),
                is_exit=True,
                is_exit_blocked=True,          #  La Sombra bloquea señuelo
                connected_to=["P0-PASILLO-A"]),
    ]

    # Planta 1
    nodos_p1 = [
        BIMNode("P1-ESCALERA-SUR","Escalera Sur P1",  1, (5.0, 6.0, 3.5),   connected_to=["P0-ESCALERA-SUR", "P1-PASILLO-B", "P2-ESCALERA-SUR"]),
        BIMNode("P1-PASILLO-B",  "Pasillo Planta 1",  1, (5.0, 3.0, 3.5),   connected_to=["P1-ESCALERA-SUR", "P1-OFICINA-A", "P1-OFICINA-B"]),
        BIMNode("P1-OFICINA-A",  "Oficina A",          1, (2.0, 3.0, 3.5),   connected_to=["P1-PASILLO-B"]),
        BIMNode("P1-OFICINA-B",  "Oficina B",          1, (8.0, 3.0, 3.5),   connected_to=["P1-PASILLO-B"]),
    ]

    # Planta 2
    nodos_p2 = [
        BIMNode("P2-ESCALERA-SUR","Escalera Sur P2",  2, (5.0, 6.0, 7.0),   connected_to=["P1-ESCALERA-SUR", "P2-PASILLO-C", "EXIT-SUR-P2"]),
        BIMNode("P2-PASILLO-C",  "Pasillo Planta 2",  2, (5.0, 3.0, 7.0),   connected_to=["P2-ESCALERA-SUR", "P2-SALA-REUNIONES"]),
        BIMNode("P2-SALA-REUNIONES","Sala Reuniones", 2, (2.0, 3.0, 7.0),   connected_to=["P2-PASILLO-C"]),
        BIMNode("EXIT-SUR-P2",   "Salida Sur P2",      2, (5.0, 9.0, 7.0),
                is_exit=True, connected_to=["P2-ESCALERA-SUR"]),
    ]

    for node in nodos_p0 + nodos_p1 + nodos_p2:
        bim.add_node(node)

    return bim


# ESCENARIO: "SOMBRA NEGRA" — Simulación completa

def run_sombra_negra_scenario() -> None:
    """
    Simula el ataque 'Sombra Negra':
      T+0:00  La Sombra: corte eléctrico + aerosol TiO₂ + señuelo ruta
      T+0:04  Cámaras ópticas: sin señal · Radar SAR + FLIR: INTACTOS
      T+0:05  MRAP activa modo Visión Rayos X
      T+0:06  HPE Edgeline calcula rutas seguras y detecta trampa
      T+0:07  Casco AR recibe hologramas guía
    """
    print("ESCENARIO: OPERACIÓN SOMBRA NEGRA — Módulo RA Proyectiva")

    # Inicialización
    bim = build_demo_bim()
    bridge = ARHelmetBridge(truck_id="IGNIS-001", bim_model=bim)

    # Riesgo estructural en zona norte (La Sombra preparó el colapso)
    bim.nodes["P0-SALA-MAQUINAS"].structural_risk = 0.85
    bim.nodes["EXIT-NORTE"].structural_risk       = 0.89

    # Mapa térmico FLIR T+0:05 (60 segundos de incendio)
    mapa_termico = {
        "ENTRADA":         35.0,   # zona segura
        "P0-PASILLO-A":   120.0,   # caliente — EPI obligatorio
        "P0-ALMACEN-1":   280.0,   # peligrosa
        "P0-SALA-MAQUINAS": 490.0, # mortal  colapso
        "EXIT-NORTE":      420.0,  # TRAMPA: cartel dice "abierta", pero 420°C
        "P0-ESCALERA-SUR":  45.0,  # templada — accesible
        "P1-ESCALERA-SUR":  50.0,  # templada
        "P1-PASILLO-B":     65.0,  # algo caliente pero pasable
        "P1-OFICINA-A":    180.0,  # caliente
        "P1-OFICINA-B":    210.0,  # caliente
        "P2-ESCALERA-SUR":  40.0,  # fría — RUTA SEGURA
        "P2-PASILLO-C":     38.0,  # fría
        "P2-SALA-REUNIONES": 35.0, # fría
        "EXIT-SUR-P2":      28.0,  # salida sur segura 
    }

    # Estado bomberos en edificio
    bomberos = [
        FirefighterStatus(
            ff_id="FF-01", position_node_id="P1-PASILLO-B",
            pos_3d=(5.0, 3.0, 3.5), heart_rate_bpm=142, spo2_percent=97,
        ),
        FirefighterStatus(
            ff_id="FF-02", position_node_id="P0-PASILLO-A",
            pos_3d=(5.0, 0.0, 0.0), heart_rate_bpm=158, spo2_percent=95,
        ),
        FirefighterStatus(
            ff_id="FF-03", position_node_id="P1-OFICINA-A",
            pos_3d=(2.0, 3.0, 3.5), heart_rate_bpm=180, spo2_percent=88,
            is_down=True,            #  bombero caído, necesita evacuación
        ),
    ]

    print("FASE 1: T+0:00 — La Sombra ejecuta el ataque")
    print("   ├──  Corte eléctrico (EMP en cuadro general)")
    print("   ├──   Aerosol TiO₂ liberado en conductos  visibilidad óptica = 0 m")
    print("   ├──  Jammer GPS activo en planta baja")
    print("   └──   Carteles LED emergencia falsificados  señuelo Salida Norte\n")

    time.sleep(0.5)

    print("FASE 2: T+0:04 — Diagnóstico de sensores")
    print("   ├──  Cámaras ópticas convencionales: SIN SEÑAL ")
    print("   ├──   FLIR infrarrojo: SEÑAL INTACTA  (infrarrojo no afectado por TiO₂)")
    print("   ├──  Radar SAR 77 GHz: SEÑAL INTACTA  (penetra humo y paredes)")
    print("   └──  MRAP: Activando modo VISIÓN RAYOS X...\n")

    time.sleep(0.5)

    print("FASE 3: T+0:05–0:07 — HPE Edgeline procesa y envía frame AR")

    # Generar frame AR
    frame = bridge.generate_ar_frame(
        thermal_map         = mapa_termico,
        firefighters        = bomberos,
        twin_alerts         = [],            # en integración real: FireTruckTwin.alerts
        optical_visibility  = False,         #  humo opaco  rayos X
        shadow_attack_active= True,          #  detectar trampas La Sombra
        start_node_id       = "ENTRADA",
    )

    # Imprimir resumen del frame
    bridge.print_frame_summary(frame)

    # Serializar a JSON (representación del paquete 5G)
    payload_json = json.dumps(frame.to_dict(), indent=2, ensure_ascii=False)
    print(" PAYLOAD AR (fragmento — transmisión 5G SA QCI-1 URLLC):")
    print(payload_json[:800] + "\n  ...[truncated]\n")

    # Resultado táctico
    if frame.escape_routes:
        best = frame.escape_routes[0]
        print(f"RUTA SEGURA RECOMENDADA: {best.exit_node_id}")
        print(f"Tiempo estimado: {best.estimated_seconds:.0f} segundos")
        print(f"Puntuación seguridad: {best.safety_score:.0%}")
        print(f"Waypoints: {'  '.join(best.waypoints)}")
    else:
        print("TODAS LAS RUTAS BLOQUEADAS — Esperar refuerzo exterior")

    if frame.shadow_trap_detected:
        print(f"TRAMPA LA SOMBRA NEUTRALIZADA:")
        print(f"Salida Norte marcada como SEÑUELO (T=420°C + riesgo colapso 89%)")
        print(f"Bomberos redirigidos automáticamente vía Salida Sur P2")

    print(f"BOMBERO FF-03: CAÍDO en P1-OFICINA-A — Equipo de rescate requerido")
    print(f"Latencia pipeline Edgeline: {frame.latency_budget_ms:.2f} ms < {AR_LATENCY_TARGET_MS} ms ")


# PUNTO DE ENTRADA

if __name__ == "__main__":
    print("IGNIS SENTINEL - Módulo RA Proyectiva")

    run_sombra_negra_scenario()
