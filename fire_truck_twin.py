"""
IGNIS SENTINEL — FireTruckTwin Digital Twin

Clase principal del Gemelo Digital del Camión de Bomberos "Ignis Sentinel".
Procesa flujos de datos JSON de sensores y dispara alertas de:
  -  Riesgo de Cavitación en la bomba de agua
  -  Desviación de Ruta Sospechosa (infiltrado / La Sombra)
  -   Anomalía CAN Bus (intento de toma de control remota)
  -   Manipulación de Combustible (ataque lógico detectado)
"""

from __future__ import annotations

import json
import math
import hashlib
import hmac
import statistics
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from collections import deque

if TYPE_CHECKING:
    from ar_helmet_bridge import ARHelmetBridge, ARHelmetFrame, FirefighterStatus


# CONSTANTES FÍSICAS Y UMBRALES

WATER_VAPOR_PRESSURE_20C = 2.34   # kPa — presión de vapor del agua a 20°C
CAVITATION_FREQ_LOW      = 600    # Hz — banda de firma acústica de cavitación
CAVITATION_FREQ_HIGH     = 800    # Hz — banda de firma acústica de cavitación
GRAVITY                  = 9.81   # m/s²
WATER_DENSITY_20C        = 998.2  # kg/m³
FUEL_ANOMALY_THRESHOLD   = 2.5   # sigma — desviación estadística para alerta combustible
ROUTE_DEVIATION_METERS   = 250    # metros de desviación máxima permitida
CAN_HMAC_SECRET          = b"HORIZONTE_CERO_SECRET_K3Y"  # En producción: desde HSM


# ENUMERACIONES

class AlertLevel(Enum):
    INFO     = "  INFO"
    WARNING  = "  ADVERTENCIA"
    ALERT    = " ALERTA"
    CRITICAL = " CRÍTICO"


class AlertType(Enum):
    CAVITATION           = "RIESGO_CAVITACION"
    ROUTE_DEVIATION      = "DESVIACION_RUTA_SOSPECHOSA"
    CAN_INTEGRITY        = "VIOLACION_INTEGRIDAD_CAN"
    FUEL_MANIPULATION    = "MANIPULACION_COMBUSTIBLE"
    THERMAL_OVERLOAD     = "SOBRECARGA_TERMICA"
    HYDRAULIC_ANOMALY    = "ANOMALIA_HIDRAULICA"
    PUMP_BEARING_FAILURE = "FALLO_COJINETE_BOMBA"


# DATACLASSES DE DATOS DEL SENSOR   

@dataclass
class HydraulicData:
    """Datos del sistema hidráulico del camión."""
    pump_inlet_pressure_kpa: float      # Presión de entrada a la bomba (kPa)
    pump_outlet_pressure_kpa: float     # Presión de salida de la bomba (kPa)
    flow_rate_lpm: float                # Caudal (litros/minuto)
    tank_level_liters: float            # Nivel del depósito (litros)
    pump_rpm: float                     # RPM de la bomba centrífuga
    bearing_temp_celsius: float         # Temperatura cojinete bomba (°C)
    fluid_temp_celsius: float           # Temperatura del fluido (°C)
    acoustic_freq_hz: float = 0.0       # Frecuencia vibración detectada (Hz)
    foam_level_percent: float = 100.0   # Nivel de espuma (%)
    valve_states: dict = field(default_factory=dict)  # Estado de válvulas


@dataclass
class MechanicalData:
    """Datos mecánicos y de telemetría del vehículo."""
    engine_temp_celsius: float          # Temperatura motor (°C)
    fuel_level_liters: float            # Nivel combustible (litros)
    fuel_consumption_lph: float         # Consumo combustible (L/hora)
    brake_temp_celsius: float           # Temperatura frenos (°C)
    engine_rpm: float                   # RPM motor principal
    vehicle_speed_kmh: float            # Velocidad vehículo (km/h)
    gross_weight_kg: float              # Peso total con carga (kg)
    odometer_km: float                  # Kilometraje acumulado


@dataclass
class GPSData:
    """Datos de posicionamiento GPS."""
    latitude: float
    longitude: float
    altitude_m: float
    heading_degrees: float
    speed_kmh: float
    timestamp: str
    fix_quality: int = 4               # 4=RTK, 3=DGPS, 2=2D, 1=GPS básico


@dataclass
class EnvironmentData:
    """Datos de sensores ambientales (Edge)."""
    ambient_temp_celsius: float         # Temperatura ambiente (°C)
    humidity_percent: float             # Humedad relativa (%)
    wind_speed_ms: float                # Velocidad viento (m/s)
    wind_direction_degrees: float       # Dirección viento (°)
    co_ppm: float                       # Concentración CO (ppm)
    co2_ppm: float                      # Concentración CO2 (ppm)
    hcn_ppm: float = 0.0               # Ácido cianhídrico (ppm)
    thermal_camera_hotspot_celsius: float = 0.0  # Punto caliente cámara térmica


@dataclass
class CANBusMessage:
    """Mensaje del bus CAN vehicular."""
    node_id: str                        # ID del nodo origen (ej. "0x7E8")
    message_id: str                     # ID del mensaje CAN
    payload: str                        # Datos en hex
    sequence_counter: int               # Contador monotónico anti-replay
    hmac_signature: Optional[str]       # Firma HMAC-SHA256 del mensaje
    timestamp: str = ""


@dataclass
class TwinAlert:
    """Alerta generada por el gemelo digital."""
    alert_type: AlertType
    level: AlertLevel
    message: str
    timestamp: str
    sensor_values: dict = field(default_factory=dict)
    recommended_action: str = ""
    forensic_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d['alert_type'] = self.alert_type.value
        d['level'] = self.level.value
        return d


# CLASE PRINCIPAL: FireTruckTwin

class FireTruckTwin:
    """
    Gemelo Digital del Camión de Bomberos "Ignis Sentinel".

    Procesa flujos de datos JSON de sensores en tiempo real y detecta:
      - Riesgo de cavitación en la bomba de agua
      - Desviación de ruta sospechosa
      - Violación de integridad del bus CAN
      - Manipulación lógica de combustible (ataque La Sombra)
      - Sobrecargas térmicas y anomalías hidráulicas

    Ejemplo de uso:
        twin = FireTruckTwin(truck_id="IGNIS-001", tank_capacity_liters=8000)
        alerts = twin.process_telemetry_json(json_payload)
    """

    def __init__(
        self,
        truck_id: str = "IGNIS-001",
        tank_capacity_liters: float = 8000.0,
        planned_route: Optional[list[tuple[float, float]]] = None,
        fuel_window_size: int = 30,
    ):
        self.truck_id         = truck_id
        self.tank_capacity    = tank_capacity_liters
        self.planned_route    = planned_route or []
        self.alerts: list[TwinAlert] = []

        # Buffers de historia para detección estadística
        self._fuel_history: deque[float] = deque(maxlen=fuel_window_size)
        self._bearing_temp_history: deque[float] = deque(maxlen=60)
        self._pump_rpm_history: deque[float] = deque(maxlen=60)
        self._can_counters: dict[str, int] = {}   # Prevención replay CAN

        # Estado interno del gemelo
        self.state: dict[str, Any] = {
            "status": "OPERATIONAL",
            "last_update": None,
            "mission_elapsed_s": 0,
            "water_autonomy_minutes": None,
        }

        print(f"[{self.truck_id}]  Gemelo Digital Ignis Sentinel INICIADO")
        print(f"[{self.truck_id}]    Capacidad tanque: {tank_capacity_liters} L")
        print(f"[{self.truck_id}]    Horizonte Cero — Modo: OPERACIONAL\n")

    # MÉTODO PRINCIPAL: process_telemetry_json

    def process_telemetry_json(self, json_payload: str | dict) -> list[TwinAlert]:
        """
        Punto de entrada principal del gemelo digital.
        Acepta un JSON como string o dict con la telemetría del camión.
        Retorna lista de alertas generadas en este ciclo.
        """
        if isinstance(json_payload, str):
            data = json.loads(json_payload)
        else:
            data = json_payload

        timestamp = data.get("timestamp", datetime.now(timezone.utc).isoformat())
        cycle_alerts: list[TwinAlert] = []

        # Parsear subsistemas
        hydraulic   = self._parse_hydraulic(data.get("hydraulic", {}))
        mechanical  = self._parse_mechanical(data.get("mechanical", {}))
        gps         = self._parse_gps(data.get("gps", {}))
        environment = self._parse_environment(data.get("environment", {}))
        can_messages= [CANBusMessage(**m) for m in data.get("can_bus", [])]

        #  MÓDULO 1: Cavitación 
        cavitation_alerts = self._check_cavitation_risk(hydraulic, environment, timestamp)
        cycle_alerts.extend(cavitation_alerts)

        #  MÓDULO 2: Desviación de Ruta 
        if gps and self.planned_route:
            route_alerts = self._check_route_deviation(gps, timestamp)
            cycle_alerts.extend(route_alerts)

        #  MÓDULO 3: Integridad CAN Bus 
        for can_msg in can_messages:
            can_alerts = self._check_can_integrity(can_msg, timestamp)
            cycle_alerts.extend(can_alerts)

        #  MÓDULO 4: Manipulación de Combustible 
        if mechanical:
            fuel_alerts = self._check_fuel_manipulation(mechanical, timestamp)
            cycle_alerts.extend(fuel_alerts)

        #  MÓDULO 5: Temperatura Motor 
        if mechanical:
            thermal_alerts = self._check_thermal_overload(mechanical, timestamp)
            cycle_alerts.extend(thermal_alerts)

        #  MÓDULO 6: Autonomía del Agua 
        if hydraulic:
            self._update_water_autonomy(hydraulic)

        # Actualizar estado del gemelo
        self.state["last_update"] = timestamp
        self.alerts.extend(cycle_alerts)

        # Imprimir alertas detectadas
        for alert in cycle_alerts:
            self._print_alert(alert)

        return cycle_alerts

    # MÓDULO 1: DETECCIÓN DE RIESGO DE CAVITACIÓN

    def _check_cavitation_risk(
        self,
        h: Optional[HydraulicData],
        env: Optional[EnvironmentData],
        timestamp: str,
    ) -> list[TwinAlert]:
        """
        Detecta riesgo de cavitación usando:
          1. Comparación de presión de entrada vs presión de vapor (física)
          2. Firma acústica en banda 600–800 Hz
          3. Gradiente térmico del cojinete
        """
        if not h:
            return []
        alerts = []

        # 1. Modelo físico: Presión de vapor del agua según temperatura
        T = h.fluid_temp_celsius
        p_vapor_kpa = self._water_vapor_pressure(T)
        npsh_available = (h.pump_inlet_pressure_kpa / (WATER_DENSITY_20C * GRAVITY / 1000)) - \
                          (p_vapor_kpa / (WATER_DENSITY_20C * GRAVITY / 1000))
        npsh_required = 3.5  # metros — valor típico de bomba bomberil

        # 2. Firma acústica: frecuencia en la banda de cavitación
        acoustic_risk = CAVITATION_FREQ_LOW <= h.acoustic_freq_hz <= CAVITATION_FREQ_HIGH

        # 3. Tendencia del cojinete (gradiente térmico)
        self._bearing_temp_history.append(h.bearing_temp_celsius)
        bearing_gradient = 0.0
        if len(self._bearing_temp_history) >= 5:
            recent = list(self._bearing_temp_history)[-5:]
            bearing_gradient = (recent[-1] - recent[0]) / 4  # °C por ciclo

        # Evaluación de riesgo combinada
        risk_score = 0.0
        risk_factors = []

        if npsh_available < npsh_required:
            risk_score += 0.5
            risk_factors.append(f"NPSH disponible ({npsh_available:.1f}m) < requerido ({npsh_required}m)")

        if acoustic_risk:
            risk_score += 0.3
            risk_factors.append(f"Firma acústica detectada: {h.acoustic_freq_hz:.0f} Hz (banda cavitación)")

        if bearing_gradient > 2.0:  # Más de 2°C de aumento por ciclo
            risk_score += 0.2
            risk_factors.append(f"Gradiente térmico cojinete: +{bearing_gradient:.1f}°C/ciclo")

        if h.pump_inlet_pressure_kpa < p_vapor_kpa:
            risk_score = 1.0  # Cavitación garantizada
            risk_factors.append(f"P_entrada ({h.pump_inlet_pressure_kpa:.1f} kPa) < P_vapor ({p_vapor_kpa:.2f} kPa) — CAVITACIÓN ACTIVA")

        # Generar alerta según nivel de riesgo
        if risk_score >= 0.8:
            alerts.append(TwinAlert(
                alert_type=AlertType.CAVITATION,
                level=AlertLevel.CRITICAL,
                message=" RIESGO DE CAVITACIÓN CRÍTICO — Daño inminente a la bomba",
                timestamp=timestamp,
                sensor_values={
                    "p_entrada_kpa": h.pump_inlet_pressure_kpa,
                    "p_vapor_kpa": p_vapor_kpa,
                    "npsh_disponible_m": round(npsh_available, 2),
                    "npsh_requerido_m": npsh_required,
                    "freq_acustica_hz": h.acoustic_freq_hz,
                    "temp_cojinete_C": h.bearing_temp_celsius,
                    "riesgo_score": round(risk_score, 2),
                },
                recommended_action="REDUCIR presión bomba 20% · ACTIVAR bomba secundaria · ALERTAR jefe de bombas",
                forensic_data={"factores_riesgo": risk_factors},
            ))
        elif risk_score >= 0.4:
            alerts.append(TwinAlert(
                alert_type=AlertType.CAVITATION,
                level=AlertLevel.WARNING,
                message="  Riesgo de Cavitación Moderado — Monitorización estrecha",
                timestamp=timestamp,
                sensor_values={
                    "p_entrada_kpa": h.pump_inlet_pressure_kpa,
                    "p_vapor_kpa": p_vapor_kpa,
                    "riesgo_score": round(risk_score, 2),
                },
                recommended_action="Monitorizar presión de entrada · Verificar filtros de succión",
                forensic_data={"factores_riesgo": risk_factors},
            ))

        return alerts

    # MÓDULO 2: DETECCIÓN DE DESVIACIÓN DE RUTA SOSPECHOSA

    def _check_route_deviation(self, gps: GPSData, timestamp: str) -> list[TwinAlert]:
        """
        Compara la posición GPS actual con la ruta planificada.
        Dispara alerta si la desviación supera ROUTE_DEVIATION_METERS.
        """
        alerts = []
        min_distance_m = float('inf')
        nearest_waypoint = None

        for wp in self.planned_route:
            dist = self._haversine_distance(
                gps.latitude, gps.longitude, wp[0], wp[1]
            )
            if dist < min_distance_m:
                min_distance_m = dist
                nearest_waypoint = wp

        if min_distance_m > ROUTE_DEVIATION_METERS:
            # Clasificar nivel según magnitud de desviación
            if min_distance_m > 1000:
                level = AlertLevel.CRITICAL
                msg = " DESVIACIÓN DE RUTA SOSPECHOSA CRÍTICA — Posible secuestro del vehículo"
                action = "ACTIVAR protocolo anti-secuestro · Contactar mando · GPS alternativo (INS)"
            elif min_distance_m > 500:
                level = AlertLevel.ALERT
                msg = " DESVIACIÓN DE RUTA ALERTA — Vehículo fuera del corredor autorizado"
                action = "Confirmar con conductor · Verificar GPS spoofing · Revisar ruta"
            else:
                level = AlertLevel.WARNING
                msg = "  Desviación de ruta moderada — Posible atasco o desvío no autorizado"
                action = "Solicitar confirmación de conductor"

            alerts.append(TwinAlert(
                alert_type=AlertType.ROUTE_DEVIATION,
                level=level,
                message=msg,
                timestamp=timestamp,
                sensor_values={
                    "lat_actual": gps.latitude,
                    "lon_actual": gps.longitude,
                    "desviacion_metros": round(min_distance_m, 1),
                    "waypoint_mas_cercano": nearest_waypoint,
                    "velocidad_kmh": gps.speed_kmh,
                    "rumbo_grados": gps.heading_degrees,
                },
                recommended_action=action,
                forensic_data={
                    "fix_quality": gps.fix_quality,
                    "threshold_metros": ROUTE_DEVIATION_METERS,
                },
            ))

        return alerts

    # MÓDULO 3: INTEGRIDAD DEL BUS CAN

    def _check_can_integrity(self, msg: CANBusMessage, timestamp: str) -> list[TwinAlert]:
        """
        Verifica la integridad de mensajes CAN mediante:
          1. Validación de firma HMAC-SHA256
          2. Detección de ataques de replay (contador monotónico)
        """
        alerts = []

        # Verificación 1: HMAC
        if msg.hmac_signature:
            expected_hmac = self._compute_can_hmac(msg)
            if not hmac.compare_digest(expected_hmac, msg.hmac_signature):
                alerts.append(TwinAlert(
                    alert_type=AlertType.CAN_INTEGRITY,
                    level=AlertLevel.CRITICAL,
                    message=f" VIOLACIÓN INTEGRIDAD CAN — Firma inválida en nodo {msg.node_id}",
                    timestamp=timestamp,
                    sensor_values={
                        "node_id": msg.node_id,
                        "message_id": msg.message_id,
                        "firma_recibida": msg.hmac_signature[:16] + "...",
                        "firma_esperada": expected_hmac[:16] + "...",
                    },
                    recommended_action=f"AISLAR nodo {msg.node_id} · Activar Playbook ALPHA · Notificar SOC",
                    forensic_data={
                        "payload_hex": msg.payload,
                        "sequence": msg.sequence_counter,
                        "timestamp_msg": msg.timestamp,
                    },
                ))
                return alerts  # No continuar con mensaje comprometido

        # Verificación 2: Replay Attack (contador monotónico)
        last_counter = self._can_counters.get(msg.node_id, -1)
        if msg.sequence_counter <= last_counter:
            alerts.append(TwinAlert(
                alert_type=AlertType.CAN_INTEGRITY,
                level=AlertLevel.CRITICAL,
                message=f" ATAQUE REPLAY CAN detectado — Nodo {msg.node_id}",
                timestamp=timestamp,
                sensor_values={
                    "node_id": msg.node_id,
                    "contador_recibido": msg.sequence_counter,
                    "contador_esperado_min": last_counter + 1,
                },
                recommended_action=f"BLOQUEAR nodo {msg.node_id} · Registrar evento forense · Notificar SOC",
                forensic_data={"payload_hex": msg.payload},
            ))
        else:
            self._can_counters[msg.node_id] = msg.sequence_counter

        return alerts

    # MÓDULO 4: MANIPULACIÓN LÓGICA DE COMBUSTIBLE (La Sombra)

    def _check_fuel_manipulation(self, mech: MechanicalData, timestamp: str) -> list[TwinAlert]:
        """
        Detecta manipulación inteligente de datos de combustible por La Sombra.
        El ataque es sutil: reduce el consumo reportado para aparentar normalidad,
        pero el gemelo detecta la incoherencia física con las RPM y el peso.

        Método:
          1. Modela el consumo esperado basado en RPM, velocidad y peso
          2. Compara con el consumo reportado
          3. Analiza la historia estadística para desviaciones anómalas
        """
        alerts = []

        # Modelo de consumo físicamente esperado (litros/hora)
        # Basado en: consumo base + factor carga + factor velocidad
        consumo_base       = 25.0   # L/h motor en ralentí
        factor_rpm         = (mech.engine_rpm / 3000.0) * 30.0
        factor_velocidad   = (mech.vehicle_speed_kmh / 100.0) * 15.0
        factor_peso        = (mech.gross_weight_kg / 20000.0) * 10.0
        consumo_esperado   = consumo_base + factor_rpm + factor_velocidad + factor_peso

        # Error relativo entre consumo esperado y reportado
        error_relativo = abs(mech.fuel_consumption_lph - consumo_esperado) / max(consumo_esperado, 1.0)

        # Análisis estadístico histórico
        self._fuel_history.append(mech.fuel_consumption_lph)

        if len(self._fuel_history) >= 10:
            media = statistics.mean(self._fuel_history)
            desv  = statistics.stdev(self._fuel_history) or 1.0
            z_score = (mech.fuel_consumption_lph - media) / desv

            # Error físico alto + z-score anómalo = manipulación probable
            if error_relativo > 0.30 and abs(z_score) > FUEL_ANOMALY_THRESHOLD:
                level = AlertLevel.CRITICAL if error_relativo > 0.50 else AlertLevel.ALERT
                alerts.append(TwinAlert(
                    alert_type=AlertType.FUEL_MANIPULATION,
                    level=level,
                    message=(
                        " MANIPULACIÓN DE COMBUSTIBLE DETECTADA — "
                        f"Error físico {error_relativo*100:.1f}% · z-score: {z_score:.2f}σ"
                    ),
                    timestamp=timestamp,
                    sensor_values={
                        "consumo_reportado_lph": mech.fuel_consumption_lph,
                        "consumo_esperado_lph": round(consumo_esperado, 2),
                        "error_relativo_pct": round(error_relativo * 100, 1),
                        "z_score": round(z_score, 2),
                        "rpm_motor": mech.engine_rpm,
                        "velocidad_kmh": mech.vehicle_speed_kmh,
                        "peso_kg": mech.gross_weight_kg,
                    },
                    recommended_action=(
                        "VERIFICAR físicamente nivel combustible · "
                        "Aislar ECU sospechoso · Activar Playbook BETA de La Sombra"
                    ),
                    forensic_data={
                        "historico_consumo": list(self._fuel_history),
                        "media_historica": round(media, 2),
                        "desviacion_estandar": round(desv, 2),
                    },
                ))

        return alerts

    # MÓDULO 5: SOBRECARGA TÉRMICA

    def _check_thermal_overload(self, mech: MechanicalData, timestamp: str) -> list[TwinAlert]:
        """Detecta sobrecargas térmicas en motor y frenos."""
        alerts = []

        # Motor
        if mech.engine_temp_celsius > 120:
            alerts.append(TwinAlert(
                alert_type=AlertType.THERMAL_OVERLOAD,
                level=AlertLevel.CRITICAL,
                message=f" TEMPERATURA MOTOR CRÍTICA: {mech.engine_temp_celsius}°C",
                timestamp=timestamp,
                sensor_values={"temp_motor_C": mech.engine_temp_celsius},
                recommended_action="DETENER operación · Enfriar motor · Inspección mecánica inmediata",
            ))
        elif mech.engine_temp_celsius > 105:
            alerts.append(TwinAlert(
                alert_type=AlertType.THERMAL_OVERLOAD,
                level=AlertLevel.WARNING,
                message=f"  Temperatura motor elevada: {mech.engine_temp_celsius}°C",
                timestamp=timestamp,
                sensor_values={"temp_motor_C": mech.engine_temp_celsius},
                recommended_action="Reducir carga · Monitorizar tendencia",
            ))

        # Frenos
        if mech.brake_temp_celsius > 400:
            alerts.append(TwinAlert(
                alert_type=AlertType.THERMAL_OVERLOAD,
                level=AlertLevel.ALERT,
                message=f" TEMPERATURA FRENOS ALTA: {mech.brake_temp_celsius}°C",
                timestamp=timestamp,
                sensor_values={"temp_frenos_C": mech.brake_temp_celsius},
                recommended_action="Aplicar frenos con suavidad · Verificar desgaste de pastillas",
            ))

        return alerts

    # SIMULACIÓN WHAT-IF: Autonomía de Agua

    def simulate_water_autonomy(
        self,
        pressure_bar: float,
        ambient_temp_celsius: float,
        hose_length_m: float = 50.0,
        hose_diameter_m: float = 0.065,
    ) -> dict:
        """
        Simula la autonomía del depósito de agua con parámetros personalizados.
        Aplica modelo físico Darcy-Weisbach para pérdidas por fricción.

        Args:
            pressure_bar: Presión de trabajo deseada (bar)
            ambient_temp_celsius: Temperatura ambiente (°C)
            hose_length_m: Longitud total de manguera (m)
            hose_diameter_m: Diámetro de manguera (m)

        Returns:
            dict con resultados de la simulación
        """
        # Propiedades del agua según temperatura
        rho = self._water_density(ambient_temp_celsius)
        mu  = self._water_viscosity(ambient_temp_celsius)

        # Pérdidas por fricción (Darcy-Weisbach)
        pressure_pa = pressure_bar * 1e5
        v_approx    = math.sqrt(2 * pressure_pa / rho)         # velocidad aprox. m/s
        re          = rho * v_approx * hose_diameter_m / mu    # número de Reynolds
        f_darcy     = 0.3164 / (re ** 0.25) if re > 4000 else 64 / re  # Blasius
        delta_p_friction = f_darcy * (hose_length_m / hose_diameter_m) * (rho * v_approx**2 / 2)

        # Caudal efectivo
        p_effective_pa = max(pressure_pa - delta_p_friction, 0)
        v_effective    = math.sqrt(2 * p_effective_pa / rho)
        area           = math.pi * (hose_diameter_m / 2) ** 2
        flow_m3_s      = area * v_effective
        flow_lpm       = flow_m3_s * 60_000

        # Factor de evaporación por temperatura
        evaporation_factor = max(0.0, (ambient_temp_celsius - 20) * 0.008)
        flow_effective_lpm = flow_lpm * (1 - evaporation_factor)

        # Calor actual del depósito
        tank_level = self.state.get("tank_level_liters", self.tank_capacity)
        autonomy_min = (tank_level / max(flow_effective_lpm, 1)) if flow_effective_lpm > 0 else 0

        # Riesgo de cavitación en estas condiciones
        p_vapor_kpa = self._water_vapor_pressure(ambient_temp_celsius)
        cavitation_risk = pressure_bar < (p_vapor_kpa / 100)

        return {
            "escenario": {
                "presion_bar": pressure_bar,
                "temp_ambiente_C": ambient_temp_celsius,
                "longitud_manguera_m": hose_length_m,
                "diametro_manguera_m": hose_diameter_m,
            },
            "hidraulica": {
                "densidad_agua_kg_m3": round(rho, 2),
                "numero_reynolds": round(re, 0),
                "regimen": "turbulento" if re > 4000 else "laminar",
                "perdida_friccion_bar": round(delta_p_friction / 1e5, 3),
                "caudal_bomba_lpm": round(flow_lpm, 1),
                "factor_evaporacion_pct": round(evaporation_factor * 100, 1),
                "caudal_efectivo_extincion_lpm": round(flow_effective_lpm, 1),
            },
            "autonomia": {
                "nivel_deposito_litros": tank_level,
                "autonomia_minutos": round(autonomy_min, 2),
                "autonomia_segundos": round(autonomy_min * 60, 0),
            },
            "alertas": {
                "riesgo_cavitacion": cavitation_risk,
                "p_vapor_kpa": round(p_vapor_kpa, 3),
                "recomendacion": (
                    " Conectar a hidrante antes de "
                    f"T+{max(0, autonomy_min-3):.1f} min"
                    if autonomy_min < 8 else " Autonomía suficiente"
                ),
            },
        }

    # MÉTODOS AUXILIARES PRIVADOS

    def _update_water_autonomy(self, h: HydraulicData) -> None:
        """Actualiza la autonomía de agua estimada en el estado del gemelo."""
        self.state["tank_level_liters"] = h.tank_level_liters
        if h.flow_rate_lpm > 0:
            self.state["water_autonomy_minutes"] = round(h.tank_level_liters / h.flow_rate_lpm, 2)

    def _water_vapor_pressure(self, temp_celsius: float) -> float:
        """Calcula presión de vapor del agua (kPa) según Antoine aproximado."""
        # Ecuación de Antoine simplificada para 0–100°C
        return math.exp(20.386 - 5132 / (temp_celsius + 273.15)) * 0.133322

    def _water_density(self, temp_celsius: float) -> float:
        """Densidad del agua (kg/m³) según temperatura."""
        T = temp_celsius
        return 1000 * (1 - abs(T - 4) / (T + 288.9) * 0.01)

    def _water_viscosity(self, temp_celsius: float) -> float:
        """Viscosidad dinámica del agua (Pa·s) según temperatura."""
        T = temp_celsius + 273.15
        return 2.414e-5 * 10 ** (247.8 / (T - 140))

    def _haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calcula distancia entre dos puntos GPS usando la fórmula Haversine (metros)."""
        R = 6_371_000  # Radio de la Tierra en metros
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlambda = math.radians(lon2 - lon1)
        a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    def _compute_can_hmac(self, msg: CANBusMessage) -> str:
        """Calcula HMAC-SHA256 de un mensaje CAN."""
        data = f"{msg.node_id}:{msg.message_id}:{msg.payload}:{msg.sequence_counter}".encode()
        return hmac.new(CAN_HMAC_SECRET, data, hashlib.sha256).hexdigest()

    def _parse_hydraulic(self, d: dict) -> Optional[HydraulicData]:
        if not d:
            return None
        return HydraulicData(**{k: v for k, v in d.items() if k in HydraulicData.__dataclass_fields__})

    def _parse_mechanical(self, d: dict) -> Optional[MechanicalData]:
        if not d:
            return None
        return MechanicalData(**{k: v for k, v in d.items() if k in MechanicalData.__dataclass_fields__})

    def _parse_gps(self, d: dict) -> Optional[GPSData]:
        if not d:
            return None
        return GPSData(**{k: v for k, v in d.items() if k in GPSData.__dataclass_fields__})

    def _parse_environment(self, d: dict) -> Optional[EnvironmentData]:
        if not d:
            return None
        return EnvironmentData(**{k: v for k, v in d.items() if k in EnvironmentData.__dataclass_fields__})

    def _print_alert(self, alert: TwinAlert) -> None:
        """Imprime alerta con formato de consola táctico."""
        sep = "═" * 70
        print(f"\n{sep}")
        print(f"  {alert.level.value} | {alert.alert_type.value}")
        print(f"  {alert.message}")
        print(f"    Timestamp: {alert.timestamp}")
        if alert.sensor_values:
            print(f"   Valores sensor: {json.dumps(alert.sensor_values, indent=4)}")
        if alert.recommended_action:
            print(f"   Acción recomendada: {alert.recommended_action}")
        print(f"{sep}\n")

    def get_status_report(self) -> dict:
        """Retorna un resumen del estado actual del gemelo digital."""
        return {
            "truck_id": self.truck_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "state": self.state,
            "total_alerts_this_session": len(self.alerts),
            "alerts_by_type": {
                atype.value: sum(1 for a in self.alerts if a.alert_type == atype)
                for atype in AlertType
            },
            "alerts_by_level": {
                level.value: sum(1 for a in self.alerts if a.level == level)
                for level in AlertLevel
            },
        }

    # MÓDULO 7: PUENTE AR PROYECTIVA (Integración con ar_helmet_bridge.py)

    def process_ar_frame(
        self,
        ar_bridge: "ARHelmetBridge",
        thermal_map: dict,
        firefighters: list,
        optical_visibility: bool = True,
        shadow_attack_active: bool = False,
        start_node_id: str = "ENTRADA",
    ) -> "ARHelmetFrame":
        """
        Genera un frame holográfico para los cascos AR usando el estado actual
        del Gemelo Digital.

        Este método actúa como puente entre FireTruckTwin y ARHelmetBridge:
          - Serializa las alertas activas del gemelo en formato dict
          - Delega la fusión BIM/térmica y el cálculo de rutas al ARHelmetBridge
          - Retorna el ARHelmetFrame listo para transmisión 5G

        Ejemplo de uso:
            from ar_helmet_bridge import ARHelmetBridge, build_demo_bim, FirefighterStatus
            bim = build_demo_bim()
            bridge = ARHelmetBridge(truck_id="IGNIS-001", bim_model=bim)
            frame = twin.process_ar_frame(
                ar_bridge=bridge,
                thermal_map={"ENTRADA": 35.0, "P0-PASILLO-A": 120.0},
                firefighters=[FirefighterStatus("FF-01", "ENTRADA", (0,0,0), 140, 97)],
                optical_visibility=False,
                shadow_attack_active=True,
            )

        Args:
            ar_bridge: Instancia de ARHelmetBridge configurada con el BIM del edificio.
            thermal_map: Mapa {node_id: temp_celsius} del sensor FLIR en tiempo real.
            firefighters: Lista de FirefighterStatus con posición y biometría.
            optical_visibility: False si humo/oscuridad bloquean visión óptica.
            shadow_attack_active: True para activar detección de trampa La Sombra.
            start_node_id: Nodo BIM desde el que calcular las rutas de escape.

        Returns:
            ARHelmetFrame — payload holográfico completo para transmisión 5G/WiFi/UWB.
        """
        # Serializar alertas activas del gemelo (últimas 20 para no sobrecargar frame)
        twin_alert_dicts = [a.to_dict() for a in self.alerts[-20:]]

        return ar_bridge.generate_ar_frame(
            thermal_map          = thermal_map,
            firefighters         = firefighters,
            twin_alerts          = twin_alert_dicts,
            optical_visibility   = optical_visibility,
            shadow_attack_active = shadow_attack_active,
            start_node_id        = start_node_id,
        )



# FUNCIÓN PRINCIPAL DE DEMOSTRACIÓN

def main():
    """Demostración del gemelo digital Ignis Sentinel con escenarios de prueba."""

    print("IGNIS SENTINEL — Demo Gemelo Digital")

    # Ruta planificada del camión (waypoints GPS)
    ruta_planificada = [
        (43.3623, -8.4115),   # Parque de Bomberos A Coruña
        (43.3650, -8.4080),   # Via rápida
        (43.3700, -8.4010),   # Punto intermedio
        (43.3780, -8.3950),   # Destino: Polígono Industrial
    ]

    # Inicializar el gemelo digital
    twin = FireTruckTwin(
        truck_id="IGNIS-001",
        tank_capacity_liters=8000,
        planned_route=ruta_planificada,
    )

    # ESCENARIO 1: Telemetría normal + Riesgo de cavitación inminente
    print("\n ESCENARIO 1: Riesgo de Cavitación en Bomba de Alta Presión \n")

    telemetria_cavitacion = {
        "timestamp": "2026-03-03T18:11:43Z",
        "hydraulic": {
            "pump_inlet_pressure_kpa": 2.0,    # Muy baja — cerca de P_vapor
            "pump_outlet_pressure_kpa": 1500.0,
            "flow_rate_lpm": 1200.0,
            "tank_level_liters": 6500.0,
            "pump_rpm": 2800.0,
            "bearing_temp_celsius": 78.0,       # Temperatura de cojinete elevada
            "fluid_temp_celsius": 42.0,          # Agua caliente por temperatura ambiente
            "acoustic_freq_hz": 720.0,           # ¡En la banda de cavitación!
            "foam_level_percent": 85.0,
            "valve_states": {"V1": "OPEN", "V2": "OPEN", "V3": "CLOSED"},
        },
        "mechanical": {
            "engine_temp_celsius": 98.0,
            "fuel_level_liters": 320.0,
            "fuel_consumption_lph": 55.0,
            "brake_temp_celsius": 180.0,
            "engine_rpm": 2500.0,
            "vehicle_speed_kmh": 0.0,           # Camión estacionado, bombeando
            "gross_weight_kg": 18500.0,
            "odometer_km": 47832.0,
        },
        "gps": {
            "latitude": 43.3780,
            "longitude": -8.3950,
            "altitude_m": 45.0,
            "heading_degrees": 90.0,
            "speed_kmh": 0.0,
            "timestamp": "2026-03-03T18:11:43Z",
            "fix_quality": 4,
        },
        "environment": {
            "ambient_temp_celsius": 40.0,
            "humidity_percent": 15.0,
            "wind_speed_ms": 8.5,
            "wind_direction_degrees": 270.0,
            "co_ppm": 450.0,
            "co2_ppm": 12000.0,
            "hcn_ppm": 8.0,
            "thermal_camera_hotspot_celsius": 680.0,
        },
        "can_bus": [],
    }

    alerts_1 = twin.process_telemetry_json(telemetria_cavitacion)

    # ESCENARIO 2: Ataque de La Sombra — Manipulación CAN Bus + Ruta
    print("\n ESCENARIO 2: Ataque de La Sombra — CAN Bus + Desvío GPS \n")

    # Calculamos HMAC correcto para comparar con uno falso
    import hmac as _hmac, hashlib as _hashlib
    fake_payload = "DEADBEEF01020304"
    fake_data = f"0x7E8:0x123:{fake_payload}:45".encode()
    correct_hmac = _hmac.new(CAN_HMAC_SECRET, fake_data, _hashlib.sha256).hexdigest()
    wrong_hmac = correct_hmac[:-4] + "XXXX"   # HMAC deliberadamente incorrecto

    telemetria_ataque = {
        "timestamp": "2026-03-03T18:15:00Z",
        "hydraulic": {
            "pump_inlet_pressure_kpa": 350.0,
            "pump_outlet_pressure_kpa": 1500.0,
            "flow_rate_lpm": 900.0,
            "tank_level_liters": 5200.0,
            "pump_rpm": 2200.0,
            "bearing_temp_celsius": 65.0,
            "fluid_temp_celsius": 22.0,
            "acoustic_freq_hz": 50.0,
            "foam_level_percent": 90.0,
            "valve_states": {"V1": "OPEN", "V2": "CLOSED"},
        },
        "mechanical": {
            "engine_temp_celsius": 95.0,
            "fuel_level_liters": 280.0,
            "fuel_consumption_lph": 8.0,    #  MANIPULADO: debería ser ~60 L/h con estas RPM
            "brake_temp_celsius": 150.0,
            "engine_rpm": 2800.0,
            "vehicle_speed_kmh": 65.0,
            "gross_weight_kg": 19000.0,
            "odometer_km": 47890.0,
        },
        "gps": {
            "latitude": 43.3900,            #  DESVIADO: 1.5 km fuera de ruta
            "longitude": -8.4500,
            "altitude_m": 60.0,
            "heading_degrees": 270.0,
            "speed_kmh": 65.0,
            "timestamp": "2026-03-03T18:15:00Z",
            "fix_quality": 1,               # Fix quality baja  posible GPS spoofing
        },
        "environment": {
            "ambient_temp_celsius": 25.0,
            "humidity_percent": 60.0,
            "wind_speed_ms": 3.0,
            "wind_direction_degrees": 180.0,
            "co_ppm": 5.0,
            "co2_ppm": 400.0,
        },
        "can_bus": [
            {   # Mensaje con HMAC incorrecto  intento de inyección
                "node_id": "0x7E8",
                "message_id": "0x123",
                "payload": fake_payload,
                "sequence_counter": 45,
                "hmac_signature": wrong_hmac,  #  Firma inválida
                "timestamp": "2026-03-03T18:15:00Z",
            },
        ],
    }

    alerts_2 = twin.process_telemetry_json(telemetria_ataque)

    # SIMULACIÓN WHAT-IF: Autonomía a 15 bar en 40°C
    print("\n SIMULACIÓN WHAT-IF: Autonomía a 15 bar · T_ambiente = 40°C \n")

    twin.state["tank_level_liters"] = 8000  # Tanque lleno para simulación
    resultado_whatif = twin.simulate_water_autonomy(
        pressure_bar=15.0,
        ambient_temp_celsius=40.0,
        hose_length_m=80.0,
    )
    print(json.dumps(resultado_whatif, indent=2, ensure_ascii=False))

    # INFORME FINAL DE ESTADO
    print("\n INFORME FINAL DE ESTADO DEL GEMELO DIGITAL \n")
    print(json.dumps(twin.get_status_report(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
