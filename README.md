# Detector de phishing — v1.0

Proyecto de aprendizaje desarrollado por etapas. Esta primera versión obtiene
capturas de páginas web como base para un futuro detector de phishing.

**Estado actual:** captura de pantalla implementada. No clasifica sitios como
legítimos o maliciosos y no incorpora todavía la privacidad y el aislamiento
previstos para la v1.1.

## Funciones

- Abre una URL con Chromium mediante Playwright, sin mostrar una ventana.
- Guarda la ventana visible o la página completa con `--full`.
- Intenta aceptar banners de cookies y cerrar algunos modales conocidos.
- Desactiva animaciones y espera a que cargue el contenido antes de capturar.
- Ofrece un modo interactivo y otro mediante argumentos de consola.

## Instalación en Windows (PowerShell)

Usa Python 3.10 o superior. La preparación de esta versión se verificó con
Python 3.13 y Playwright 1.65.2.

Desde la carpeta del proyecto:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m playwright install chromium
```

El entorno `.venv` mantiene las dependencias de este proyecto separadas de las
de otros proyectos. No es una barrera de seguridad para navegar sitios.
La descarga de Chromium se realiza por separado de la instalación de Playwright.

## Uso

Modo interactivo:

```powershell
.\.venv\Scripts\python.exe main.py
```

Puedes introducir un dominio sin `https://` en el modo interactivo. Deja la
entrada vacía para salir y pulsa Enter cuando aparezca la pausa final.

Desde la línea de comandos, utiliza la URL completa:

```powershell
.\.venv\Scripts\python.exe main.py https://example.com capturas/ejemplo.png
.\.venv\Scripts\python.exe main.py https://example.com capturas/ejemplo-completo.png --full
.\.venv\Scripts\python.exe main.py --help
```

Si omites el archivo de salida, se genera un nombre basado en el dominio en
la carpeta actual. Una captura nueva puede sobrescribir otra con el mismo nombre.

## Límites de la v1.0

El navegador realiza conexiones reales y ejecuta JavaScript del sitio. Su
contexto nuevo no oculta la IP ni proporciona aislamiento de red. Los botones
de cookies pueden aceptar cookies; el resultado depende de cada página.
Usa páginas de prueba conocidas durante esta etapa y evita introducir datos
personales. Una captura no demuestra que una página sea segura.

## Archivos del proyecto

| Archivo | Propósito |
| --- | --- |
| `main.py` | Código original de captura de la v1.0. |
| `requirements.txt` | Versión de la dependencia directa. |
| `.gitignore` | Exclusiones para Git: entorno, capturas y archivos locales sensibles. |
| `.gitattributes` | Normalización de finales de línea en archivos de texto. |
| `CHANGELOG.md` | Historial de cambios por versión. |
| `GUIA_GITHUB.md` | Pasos para publicar en un repositorio privado. |

## Siguiente etapa

La v1.1 abordará privacidad y aislamiento. Su diseño e implementación quedan
pendientes; este repositorio conserva el comportamiento original de la v1.0.
