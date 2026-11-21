# Historial de cambios

## v1.1

- Aplicación de escritorio para Windows con análisis local y advertencias explicadas.
- Captura pasiva opcional y distribución como ejecutable con Chromium incluido.
- Reglas de análisis independientes de la interfaz.
- Análisis sin conexión del dominio, HTTP, direcciones IP, credenciales en enlaces, caracteres internacionales y similitud con marcas.
- Corregida la vista previa sin estilos en páginas que cargan recursos desde otros dominios. Se validan los destinos públicos y se permite JavaScript para renderizar contenido dinámico.
- La imagen se muestra a resolución original cuando cabe en la pantalla.

## v1.0

Primera versión preparada para control de versiones.

- Captura de páginas web con Python, Playwright y Chromium.
- Modo interactivo y ejecución con argumentos.
- Captura de ventana o página completa mediante `--full`.
- Intentos de cierre de banners de cookies y modales.
- Documentación de instalación y publicación, dependencia directa fijada y
  exclusiones de archivos locales para Git.

No incluye detección de phishing ni las medidas previstas para la v1.1.
