# CyberSecurity Toolkit (All in One)

Aplicacion de escritorio en Python con interfaz tipo "hacker" para aprendizaje defensivo y pruebas eticas.

## Modulos incluidos

- Escaner de redes WiFi y dispositivos locales (IP/MAC)
- Monitor de conexiones y procesos con puertos sospechosos
- Gestor de contrasenas cifrado con AES-GCM y clave maestra
- Encriptador/desencriptador de archivos
- Simulador etico de fuerza bruta (solo estimacion)
- Dashboard unificado con metricas

## Requisitos

- Python 3.10+
- Windows (el escaneo WiFi usa `netsh`)

Instalar dependencias:

```powershell
pip install -r requirements.txt
```

## Ejecutar

```powershell
python Toolkit-All-in-One.py
```

## Notas de seguridad

- Esta herramienta esta orientada a aprendizaje y defensa.
- El simulador no realiza ataques reales; solo calcula probabilidades/tiempos.
- Usa siempre redes y sistemas propios o con autorizacion.

## Ejecutar tests

```powershell
python -m unittest discover -s tests -v
```

