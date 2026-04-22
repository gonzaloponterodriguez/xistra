<div align="center">
  <h1> Ignis Sentinel</h1>
  <p><b>Gemelo Digital de Camión de Bomberos de Alta Capacidad</b></p>
  <p><i>Proyecto desarrollado para la Fase 2 del Tech Challenge de HPECDS</i></p>
</div>

---

## Resumen Ejecutivo
**Ignis Sentinel** es un Sistema de Gemelo Digital avanzado diseñado para monitorizar, simular y proteger de forma autónoma vehículos pesados de extinción de incendios. Desarrollado como propuesta para la **Fase 2 del Tech Challenge de HPECDS**, el sistema procesa en tiempo real datos de cuatro capas críticas del vehículo y está dotado de múltiples sistemas de Inteligencia Artificial en el *Edge* para la toma rápida de decisiones. Destaca por su alta resistencia a ciberataques, particularmente dirigidos por adversarios avanzados como el grupo terrorista conocido como "La Sombra".

### Módulos Principales
* **Motor Base (FireTruckTwin)**: Modelado físico en tiempo real de hidráulica, cinemática, biometría y desgaste térmico.
* **Módulo de Realidad Aumentada Proyectiva (MRAP)**: Fusión de modelos BIM, termografía infrarroja y cálculo de rutas de escape seguras, proyectando visión "Rayos X" en cascos holográficos (ej: HoloLens 2) vía 5G privado con latencia ultra baja.
* **Módulo de Enjambre de Drones (MED)**: Orquestación K3s/Kubernetes de enjambres de drones térmicos para reconocimiento perimetral, fusión bayesiana de cámaras FLIR en modelos tridimensionales y IA autónoma para redirigir la presión de los cañones de agua si detecta vida humana atrapada.
* **Módulo de Ciberseguridad Industrial (MCI)**: Defensa en profundidad con Caja Negra Inmutable (Hash DLT), verificación continua *Silicon Root of Trust* (TPM 2.0 y iLO 6), y un innovador *Safe Mode* con aislamiento de bus CAN para evitar telemetrías manipuladas o *spoofing* GPS.

---

## Arquitectura Edge-Fog-Cloud

El sistema opera bajo un flujo ininterrumpido a través de tres dominios computacionales:
1. **Edge**: Procesamiento en el propio vehículo para fusión térmica (MRAP) e inferencia YoloV8 (MED).
2. **Fog**: Transmisión de hologramas a rasantes de terreno. 
3. **Cloud**: Almacén profundo de Big Data de telemetría y entrenamiento continuado de redes neuronales contra riesgos predictivos.

---

## Estructura del Repositorio

```text
fase2/
├── fire_truck_twin.py            # Módulo motor base del Gemelo Digital.
├── ar_helmet_bridge.py           # Módulo RA Proyectiva (BIM+FLIR+A*+5G).
├── drone_swarm_orchestrator.py   # Módulo Enjambres Drones (K3s+Fusión 3D+IA Cañones).
├── cybersecurity_sentinel.py     # Módulo Ciberseguridad (DLT+SRoT+SafeMode+BioAuth).
├── main.py                       # API Gateway FastAPI (PoC Wrapper).
├── sample_telemetry.json         # Dataset mock con métricas para pruebas lógicas.
├── docker-compose.yml            # Orquestador del servicio Dockerizado (Ignis AI, Grafana, InfluxDB).
├── Dockerfile                    # Instrucciones de compilado de la imagen base.
├── requirements.txt              # Dependencias pip del proyecto Python.
└── grafana/                      # Provisioning automatizado para dashboards Grafana.
```

## Requisitos Previos

Para ejecutar los scripts puramente locales de simulación lógica:
* **Python 3.9** o superior.
* No se requieren dependencias externas complejas, el core está diseñado sobre la estándar library. 

Para ejecutar la **Prueba de Concepto (PoC) Completa Integrada (API + Monitorización)**:
* **Docker** motor (v20.10+).
* **Docker Compose** (v2.x+).

---

## Instalación y Ejecución de Pruebas

El proyecto "Ignis Sentinel" está diseñado para ser evaluado en dos modalidades: **(1) Simulaciones Modulares por Consola** y **(2) Prueba de Concepto Completa vía Docker**. Siga los pasos de verificación a continuación para testear cada característica.

### 1. Simulaciones Modulares (Scripts de Python Locales)

Abra su consola (Terminal/PowerShell), navegue a la carpeta del proyecto y ejecute los módulos unitarios para probar la lógica subyacente de cada uno de ellos. Observe las trazas simuladas en consola:

**A. Probar el Modulo Base del Gemelo Digital:**
Este script verifica que el gemelo inicializa sus sensores correctamente (GPS, Hidráulica, CAN) y carga información simulada.
```bash
python fire_truck_twin.py
```
> **Test Esperado:** Verá por consola "Inicializando sensores simulados..." y se calculará el estado de la bomba de agua sin errores.

**B. Probar el Módulo de Realidad Aumentada (MRAP):**
Demuestra la fusión del modelo BIM, rutas A* para sortear obstáculos y renderización para el casco del bombero ante un apagón.
```bash
python ar_helmet_bridge.py
```
> **Test Esperado:** Un informe detallado indicará eventos como alerta de baja presión, detección de calor anómalo, cálculo de ruta de escape segura para el Bombero FF-01 por el "P0-PASILLO-A" y transmisión exitosa a través del enlace 5G.

**C. Probar el Módulo de Enjambre de Drones (MED):**
Ejecuta la orquestación simulada de 4 drones sobre clúster K3s, inyecta calor térmico tridimensional y realiza la detección de humanos.
```bash
python drone_swarm_orchestrator.py
```
> **Test Esperado:** Observará logs simulando el arranque de pods en K3s, recolección de nubes de puntos FLIR y, tras inyectar un falso positivo, el mensaje crítico `[IA CAÑÓN] ATENCIÓN: HUMANO DETECTADO EN ZONA BLOQUEADA`, que detona el recálculo automático de la presión del camión a 850 KPa.

**D. Probar el Módulo Ciberseguridad Industrial (MCI):**
Ejecuta la comprobación por firmas (TPM 2.0 ficticia) y defiende al vehículo ante un ataque de "La Sombra" intentando Falsear coordenadas GPS.
```bash
python cybersecurity_sentinel.py
```
> **Test Esperado:** La terminal arrojará registros del Digital Black Box firmando bloques. Posteriormente, detectará un `GPS_VELOCITY_MISMATCH`, emitiendo una severidad crítica que corta el bus CAN, finalizando con el éxito de `SafeMode Interlocking Engaged` y petición de biometría Iris+Huella.

---

### 2. Prueba de Concepto Integrada (Docker Plug & Play)

Para ver a Ignis Sentinel operando como un motor backend accesible como web service (FastAPI) emitiendo telemetría hacia bases de datos de series temporales (InfluxDB) de cara a visualización (Grafana). 

1. Sitúese en la raíz del proyecto (donde se ubica `docker-compose.yml`) y lance los contenedores:
```bash
docker compose up --build -d
```
2. Verifique que los cinco contenedores corren sin problema:
```bash
docker ps
```
> **Test Esperado:** Verá corriendo `ignis-ai-engine`, `ignis-grafana`, `ignis-influxdb`, `ignis-orion-ld` y `ignis-mongo` en estado `Up`.

####  Pruebas de la API vía Interfaz Interactiva (SwaggerUI):
1. Abra su explorador web en: [http://localhost:8443/docs](http://localhost:8443/docs)
2. Despliegue el endpoint **`GET /api/v1/thermal-fusion`**. Presione **"Try it out"** y luego **"Execute"**. 
   - **Resultado Test:** En Response Body verá un objeto JSON que representa un `ar_helmet_frame_payload` emulando lo que el vehículo envía vía 5G a los cascos con firmas térmicas.
3. Despliegue el enpoint **`POST /api/v1/safemode/trigger`**. Presione **"Try it out"** y modifique la request si gusta, o use la de por defecto. Presione **"Execute"**.
   - **Resultado Test:** Observará un Payload confirmando `"status": "Safe Mode Activated"` ante una Inyección GPS introducida, revelando metadatos completos del evento.


####  Monitorización HUD (Grafana/Influx):
Una vez la PoC lleve unos minutos arriba:
- **Grafana HUD del Comandante:** [http://localhost:3000](http://localhost:3000) (El DataSource hacia InfluxDB ya figura Auto-Aprovisionado por Docker).
- **InfluxDB Dashboard Raw:** [http://localhost:8086](http://localhost:8086) 
  *(Usuario `admin` | Password `ignis_admin_123`)*

---
<div align="center">
  <img src="https://img.shields.io/badge/Status-Activo-success" alt="Status" />
  <img src="https://img.shields.io/badge/Python-3.9+-blue" alt="Python Version" />
</div>

