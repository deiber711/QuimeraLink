# Detector de phishing · v1.1 para Windows

Abre el ejecutable **DetectorDePhishing.exe**, pega un enlace y pulsa **Analizar enlace**. El programa muestra el dominio de destino y explica las señales encontradas. Revisa la dirección en tu equipo sin abrirla, enviarla a un servicio ni guardar un historial. Un resultado sin señales deja la autenticidad del sitio sin confirmar.

**Ver captura** visita la dirección desde tu conexión. El sitio puede ver tu IP y recibir identificadores incluidos en el enlace. La vista previa muestra una imagen en memoria. Usa un perfil temporal de Chromium con su sandbox, JavaScript habilitado para dibujar la página y descargas deshabilitadas. Solo solicita recursos HTTP o HTTPS públicos, incluidos estilos, fuentes e imágenes de otros dominios, sin seguir redirecciones HTTP ni pulsar botones. Algunas páginas se verán incompletas o no cargarán. Cierra la ventana para descartar la imagen.

## Alcance de las reglas

El análisis identifica HTTP sin cifrar, direcciones numéricas, credenciales en la URL, nombres internacionales y similitudes sencillas con PayPal y Bancolombia. Son indicios que también pueden aparecer en sitios legítimos. La revisión se limita a la dirección escrita. La captura opcional no modifica el resultado.

## Desarrollo y distribución

Desde Windows con Python 3.10 o superior y Tkinter:

```powershell
python -m pip install -r requirements.txt
python -m playwright install chromium
python main.py
python -m unittest
```

Para generar la descarga que se distribuye a los usuarios:

```powershell
python -m pip install pyinstaller
.\construir.ps1
```

El archivo resultante es `dist/DetectorDePhishing.exe`. Incluye Python, la interfaz y Chromium. El usuario solo necesita el ejecutable. La compilación usa la revisión de Chromium correspondiente a la versión de Playwright instalada.

## Consola

```powershell
python main.py https://example.com
python main.py https://example.com --captura
python main.py https://example.com capturas/ejemplo.png --full
```

Una URL sola solicita análisis. Una ruta de salida, `--captura` o `--full` solicita también la imagen. La consola puede conservar los argumentos en su historial. Para enlaces sensibles, utiliza la ventana de escritorio.

## Reutilización

`analisis.analizar(texto)` devuelve el dominio normalizado, las señales y la dirección apta para una captura opcional. La dirección puede contener parámetros privados y debe tratarse como dato sensible. El módulo usa solo la biblioteca estándar y puede llamarse desde otra interfaz o un servicio Python. Los casos en `test_analisis.py` sirven de referencia para futuros clientes. La interfaz está en `escritorio.py` y la navegación en `captura.py`.
