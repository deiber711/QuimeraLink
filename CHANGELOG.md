# Historial de cambios

## En desarrollo

- Dictamen de riesgo en consola con salida JSON mediante `--json`. Incluye el puntaje, los motivos, las fuentes y las limitaciones del análisis.
- El informe de red muestra los dominios contactados por TCP, los destinos anunciados en las redirecciones y los errores de validación de certificados TLS.
- Se retira la guía de publicación inicial `GUIA_GITHUB.md`.

- Analizadores de URL y marca separados e integrados en escritorio y consola. La URL se analiza localmente con la lista de sufijos incluida, normalización IDNA y señales para IP literales, credenciales y acortadores.
- Catálogo local de 197 marcas, entidades y servicios, incluidas Agaval y Falabella Colombia. Registra 265 referencias de dominios y hosts y distingue 16 sufijos de plataformas de acceso compartidas.
- Relaciones documentadas entre entidades y proveedores de autenticación en hosts exactos. La inspección identifica el salto al proveedor y muestra las señales de marca de cada destino anunciado.
- El análisis de marca distingue menciones informativas, imitaciones del nombre y solicitudes de acceso. El informe identifica al proveedor de una plataforma compartida y aclara cuándo la organización cliente sigue sin verificarse.
- Detección de nombres parecidos y caracteres confusos en dominios y subdominios, con coincidencias oficiales verificadas y 35 puntos sugeridos por indicios de suplantación.
- La inspección compara dominios registrables en cada redirección, distingue el origen final del destino anunciado y señala HTML que menciona una marca y solicita datos desde un dominio ajeno a su catálogo.
- Reputación sin conexión con copias actualizables de PhishTank y CERT Polska. El informe registra la fuente, la fecha, el alcance de la coincidencia y la vigencia de la copia, también para destinos anunciados por redirecciones.
- Consulta opcional DNS/RDAP en escritorio y consola. Registra la respuesta DNS, los datos y la antigüedad disponibles para el dominio, con cobertura para `.co` a través de su operador.
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
