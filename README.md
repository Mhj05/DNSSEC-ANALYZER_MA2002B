# DNSSEC Analyzer — MA2002B

Análisis del estado de implementación de **DNSSEC** en una muestra de 99 dominios bajo el TLD `.mx`, desarrollado como parte del reto de **Análisis de Criptografía y Seguridad (MA2002B)** del Tecnológico de Monterrey.

El proyecto consulta en vivo los registros **DNSKEY, RRSIG, DS, NSEC/NSEC3/NSEC3PARAM** de cada dominio, verifica la cadena de confianza desde la raíz (`.`) hasta cada dominio, y genera un dashboard interactivo, gráficas estáticas, un árbol de cadena de confianza y un Excel/CSV con los resultados.

---

## Contenido del repositorio

| Archivo | Descripción |
|---|---|
| `cripto_reto.py` | Script principal. Realiza todas las consultas DNS en vivo (DNSKEY, RRSIG, DS, NSEC/NSEC3), construye el árbol de cadena de confianza y exporta `dnssec_results.json`. |
| `generar_reporte.py` | Lee `dnssec_results.json` y genera el dashboard (`reporte_dnssec.html`), el Excel (`resultados_dnssec.xlsx`) y dos imágenes PNG (`metricas_dashboard.png`, `arbol_confianza.png`). |
| `dnssec_results.json` | Salida cruda del análisis (se genera al correr `cripto_reto.py`; no es necesario subirlo si se va a regenerar). |
| `reporte_dnssec.html` | Dashboard interactivo: tarjetas de métricas, gráficas (donas/barras con D3.js) y árbol de cadena de confianza interactivo. |
| `resultados_dnssec.xlsx` | Resultados en Excel, con hojas: Resumen, DNSKEY, RRSIG, DS, NSEC, Cadena_Confianza. |
| `metricas_dashboard.png` | Imagen estática con las 6 gráficas de métricas globales (para insertar en el reporte/presentación). |
| `arbol_confianza.png` | Imagen estática del árbol de cadena de confianza completo. |

---

## Requisitos

- **Python 3.10+**

### Librerías a instalar

```bash
pip install dnspython pandas openpyxl matplotlib networkx
```

| Librería | Uso |
|---|---|
| [`dnspython`](https://www.dnspython.org/) | Construcción y envío de consultas DNS con el bit DO (DNSSEC OK), parseo de registros DNSKEY/RRSIG/DS/NSEC/NSEC3. |
| `pandas` | Construcción de las tablas de resultados para el Excel y el HTML. |
| `openpyxl` | Motor de escritura para archivos `.xlsx` (usado por pandas). |
| `matplotlib` | Generación de las gráficas estáticas (PNG) de métricas y del árbol. |
| `networkx` | Construcción y dibujo del grafo jerárquico del árbol de cadena de confianza. |

`hashlib`, `struct`, `json`, `datetime`, `sys`, `pathlib`, `html` son parte de la librería estándar de Python y no requieren instalación.

---

## Uso

### 1. Ejecutar el análisis DNSSEC

```bash
python cripto_reto.py
```

Esto consulta el resolver `8.8.8.8` para cada uno de los 99 dominios definidos en `DOMAINS` (dentro del script), imprime un reporte en consola y genera `dnssec_results.json` en el directorio actual.

> ⏱️ Nota: el script hace múltiples consultas DNS por dominio (DNSKEY, RRSIG, DS, NSEC/NSEC3, más todas las consultas del árbol de cadena de confianza), por lo que puede tardar varios minutos dependiendo de la latencia de red.

### 2. Generar el dashboard, Excel y gráficas

```bash
python generar_reporte.py dnssec_results.json
```

Esto genera, en el mismo directorio (o en la carpeta opcional indicada como segundo argumento):

- `resultados_dnssec.xlsx`
- `reporte_dnssec.html` → abrir con doble clic en cualquier navegador
- `metricas_dashboard.png`
- `arbol_confianza.png`

```bash
# Ejemplo guardando en una subcarpeta "out"
python generar_reporte.py dnssec_results.json out
```

---

## Interpretación general de resultados

- **DNSKEY** → el dominio publica al menos una clave pública (requisito mínimo de DNSSEC).
- **RRSIG** → existe al menos una firma digital sobre un RRset (A o, como respaldo, SOA), clasificada como VÁLIDA, EXPIRADA o futura según la fecha de la consulta.
- **DS / cadena de confianza** → se recalcula criptográficamente el hash DS a partir de la DNSKEY del dominio (RFC 4034 §5.1.4) y se compara con el DS publicado en la zona padre. Si coincide, la cadena es íntegra; si no, está rota o desalineada (caso típico de un *KSK rollover* incompleto).
- **NSEC vs NSEC3** → NSEC3 (recomendado, RFC 5155) usa hashes para negar la existencia de un nombre sin revelar la estructura de la zona; NSEC expone el "siguiente nombre" y permite *zone walking*.

El árbol de cadena de confianza usa el siguiente código de color:

- 🔵 Azul — raíz `.` (ancla de confianza, RFC 4033)
- 🟢 Verde — DNSSEC OK (DNSKEY + DS + cadena verificada)
- 🟡 Amarillo — DNSKEY presente pero cadena incompleta o no verificable
- ⚪ Gris — sin DNSSEC (sin DNSKEY)

---

## RFCs de referencia

RFC 4033, 4034, 4035 (DNSSEC-bis), RFC 4509 (DS SHA-256), RFC 5011 (gestión automatizada de claves), RFC 5155 (NSEC3), RFC 6605 (ECDSA para DNSSEC), RFC 6781 (prácticas operativas), RFC 6840 (aclaraciones DNSSEC), RFC 8624 (recomendaciones de algoritmos), RFC 9364 (consolidación DNSSEC).

---

## Equipo

MA2002B Análisis de Criptografía y Seguridad (Grupo 302) — Dr. Alberto F. Martinez
Tecnológico de Monterrey
