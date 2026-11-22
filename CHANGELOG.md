# Historial de cambios

## En desarrollo

- Analizadores de URL y marca separados e integrados en escritorio y consola. La URL se analiza localmente con la lista de sufijos incluida, normalización IDNA y señales para IP literales, credenciales y acortadores.
- Catálogo local de 197 marcas, entidades y servicios, incluidas Agaval y Falabella Colombia. Registra las fuentes de 262 dominios y hosts y distingue 13 sufijos de autenticación compartida.
- Detección de nombres parecidos y caracteres confusos en dominios y subdominios, con coincidencias oficiales verificadas y 35 puntos sugeridos por indicios de suplantación.
- La inspección compara dominios registrables en cada redirección, distingue el origen final del destino anunciado y señala HTML que menciona una marca y solicita datos desde un dominio ajeno a su catálogo.
- Lanzador de desarrollo `iniciar.cmd`, dependencias de pruebas y suite `pytest` para referencias oficiales, redirecciones, imitaciones y enlaces acortados.

## v1.2

- Inspección web opcional en escritorio y consola con `--inspeccionar`.
- Recorrido de redirecciones, estados HTTP, dominio final, título y destinos de formularios a partir del HTML estático.
- Señales de cambios de dominio, redirecciones de HTTPS a HTTP y formularios de contraseña con destinos de otro origen o sin cifrado.
- Validación de destinos públicos en cada salto, límites de tiempo y tamaño e informes parciales cuando la inspección se interrumpe.

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
