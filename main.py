import os
import time
import random
import threading
from fastapi import FastAPI, Body
from dataclasses import asdict
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

from fire_truck_twin import FireTruckTwin
from ar_helmet_bridge import ARHelmetBridge, build_demo_bim, FirefighterStatus
from cybersecurity_sentinel import SafeModeProtocol, DigitalBlackBox, ContradictionType, TelemetryContradiction

app = FastAPI(
    title="Ignis Sentinel API",
    description="API para Ignis Sentinel Digital Twin PoC",
    version="1.0"
)

# Initialize global components for the PoC
truck_id = "IGNIS-001"
twin = FireTruckTwin(truck_id=truck_id, tank_capacity_liters=8000)
bim = build_demo_bim()
bridge = ARHelmetBridge(truck_id=truck_id, bim_model=bim)
dlt = DigitalBlackBox(truck_id=truck_id)
safe_mode = SafeModeProtocol(truck_id=truck_id, dlt_blackbox=dlt)

# InfluxDB Configuration
INFLUXDB_URL = os.getenv("INFLUXDB_URL", "http://localhost:8086")
INFLUXDB_TOKEN = os.getenv("INFLUXDB_TOKEN", "ignis_secret_token_123")
INFLUXDB_ORG = os.getenv("INFLUXDB_ORG", "ignis_org")
INFLUXDB_BUCKET = os.getenv("INFLUXDB_BUCKET", "ignis_bucket")

try:
    influx_client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
    write_api = influx_client.write_api(write_options=SYNCHRONOUS)
except Exception as e:
    print(f"Error inicializando InfluxDB Client: {e}")
    write_api = None

def telemetry_simulation_loop():
    """Background task to simulate and send telemetry to InfluxDB."""
    print(f"[{truck_id}] Iniciando simulador de telemetría hacia InfluxDB...")
    while True:
        if write_api:
            try:
                # Generar datos simulados de telemetría del camión
                pump_pressure = random.uniform(800.0, 1200.0)  # kPa
                flow_rate = random.uniform(1500.0, 2500.0)     # L/min
                engine_temp = random.uniform(85.0, 95.0)       # °C
                tank_level = 8000.0 - (time.time() % 3600) * 2 # Consumo de agua simulado
                
                # Crear un punto de telemetría para InfluxDB
                point = (
                    Point("fire_truck_telemetry")
                    .tag("truck_id", truck_id)
                    .field("pump_pressure_kpa", round(pump_pressure, 2))
                    .field("flow_rate_lpm", round(flow_rate, 2))
                    .field("engine_temp_celsius", round(engine_temp, 2))
                    .field("tank_level_liters", round(max(0.0, tank_level), 2))
                )
                
                # Escribir en base de datos
                write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
            except Exception as e:
                print(f"Error escribiendo en InfluxDB: {e}")
        
        # Enviar cada 2 segundos
        time.sleep(2.0)

# Iniciar el hilo de telemetría en segundo plano
threading.Thread(target=telemetry_simulation_loop, daemon=True).start()

@app.get("/")
def read_root():
    return {"status": "Ignis Sentinel AI Engine Running", "truck_id": truck_id}

@app.get("/api/v1/thermal-fusion")
def get_thermal_fusion():
    """
    Simula envio de telemetria de sensores termicos y recupera el AR Helmet Frame
    con datos de mapa de calor fusionados en 3D.
    """
    frame = twin.process_ar_frame(
        ar_bridge=bridge,
        thermal_map={"ENTRADA": 35.0, "P0-PASILLO-A": 120.0, "EXIT-SUR-P2": 28.0},
        firefighters=[FirefighterStatus("FF-01", "P1-PASILLO-B", (5.0, 3.0, 3.5), 142, 97)],
        optical_visibility=False,
        shadow_attack_active=False,
    )
    return {"status": "success", "frame": frame.to_dict()}

@app.post("/api/v1/safemode/trigger")
def trigger_safe_mode(
    payload: dict = Body(default={"attack_type": "telemetry_injection", "severity": 3})
):
    """
    Simula ataque de 'La Sombra' inyectando telemetria contradictoria.
    Activa el Protocolo de Modo Seguro.
    """
    # Crea contradicciones mock
    contradictions = [
        TelemetryContradiction(
            contradiction_type=ContradictionType.FUEL_PHYSICS_MISMATCH,
            description="La Sombra injection: reported consumption vs physical models divergence >70%",
            sensor_a_value=0, sensor_b_value=100, delta_percent=100.0, 
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            severity=payload.get("severity", 3)
        ),
        TelemetryContradiction(
            contradiction_type=ContradictionType.GPS_VELOCITY_MISMATCH,
            description="GPS spoofing detected",
            sensor_a_value=120, sensor_b_value=0, delta_percent=100.0,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            severity=payload.get("severity", 3)
        )
    ]
    
    if safe_mode.evaluate_safe_mode_trigger(contradictions):
        event = safe_mode.activate_safe_mode(contradictions)
        return {"status": "Safe Mode Activated", "event": asdict(event)}
    else:
        return {"status": "No critical contradiction. Operational."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8443)
