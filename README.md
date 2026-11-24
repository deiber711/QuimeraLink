# Detector de phishing · v1.2 para Windows

Abre el ejecutable **DetectorDePhishing.exe**, pega un enlace y pulsa **Analizar enlace**. El programa muestra el nombre de host de destino, el dominio registrable cuando existe y las señales encontradas. Revisa la dirección en tu equipo sin abrirla, enviarla a un servicio ni guardar un historial. Un resultado sin señales deja la autenticidad del sitio sin confirmar.

Pulsa **Actualizar listas de reputación** para consultar a los proveedores y guardar sus listas en el equipo. Después, **Analizar enlace** busca coincidencias en esas copias incluso sin conexión. La actualización descarga listas completas y prescinde de la dirección que esté en el campo de texto.

Después de analizar el enlace, **Consultar DNS/RDAP** comprueba el host y busca el registro del dominio. Google Public DNS y el operador del registro reciben los nombres consultados y ven la IP de la conexión. El programa conserva la consulta en memoria y omite la ruta, parámetros, fragmento y credenciales.

**Inspeccionar página** visita el enlace desde tu conexión. Muestra los orígenes y estados HTTP del recorrido, el origen final, su dominio registrable, el título y los destinos declarados por los formularios del HTML estático. Sigue hasta cinco redirecciones y valida cada salto antes de conectarse. Señala los cambios de dominio registrable y los saltos de HTTPS a HTTP, así como los formularios con campos de contraseña o datos financieros que apuntan a otro origen o a una dirección HTTP. Si el recorrido se interrumpe, identifica el último origen que respondió e indica el destino anunciado cuando el servidor lo proporcionó en una redirección válida. La inspección usa solicitudes GET, sin ejecutar JavaScript, cargar recursos de la página ni enviar formularios.

Para identificar campos sensibles, el inspector lee el tipo de control, las indicaciones de autocompletado, los nombres y las etiquetas. Reconoce, entre otros, números de tarjeta, códigos de seguridad e identificadores de cuenta bancaria. Comprueba el origen declarado por el formulario y las alternativas de sus botones, incluidos los controles asociados mediante `form`. Los formularios y destinos creados por JavaScript quedan fuera del análisis estático.

El informe de red enumera los dominios con los que se estableció una conexión TCP, en orden de primer contacto. Cada redirección muestra el origen anunciado, incluso si el siguiente salto quedó bloqueado. Si la validación del certificado falla, la inspección se detiene y muestra el origen afectado y el motivo disponible. HTTPS cifra la conexión. La legitimidad del sitio requiere evidencia adicional.

El sitio puede ver tu IP y recibir los identificadores presentes en el enlace. La inspección mantiene los resultados en memoria. Las direcciones del informe omiten las rutas y los parámetros. El sitio proporciona el título mostrado.

La inspección también contrasta las marcas mencionadas en el título o en texto cercano a una solicitud con el dominio de la página. La señal requiere evidencia de un campo para datos personales o credenciales en el HTML recibido.

**Ver captura** visita la dirección desde tu conexión. El sitio puede ver tu IP y recibir identificadores incluidos en el enlace. La vista previa muestra una imagen en memoria. Usa un perfil temporal de Chromium con su sandbox, JavaScript habilitado para dibujar la página y descargas deshabilitadas. Solo solicita recursos HTTP o HTTPS públicos, incluidos estilos, fuentes e imágenes de otros dominios, sin seguir redirecciones HTTP ni pulsar botones. Algunas páginas se verán incompletas o no cargarán. Cierra la ventana para descartar la imagen.

## Alcance de las reglas

- `tldextract` separa el dominio registrable, la etiqueta principal, el subdominio y el sufijo. Usa la Public Suffix List incluida y una caché local en memoria. La lista incluye sufijos como `com.co` y `co.uk`, comodines, excepciones y plataformas como `github.io`. Cuando no hay una regla aplicable se usa la regla por defecto de la lista. [tldextract](https://pypi.org/project/tldextract/) · [Public Suffix List](https://publicsuffix.org/list/)
- Para nombres internacionales, el destino se muestra en Punycode y también se ofrece el nombre en Unicode. Las señales cubren caracteres visualmente confundibles y mezclas de escritura latina, griega y cirílica dentro de una etiqueta. [Unicode UTS #39](https://www.unicode.org/reports/tr39/)
- El catálogo local compara palabras distintivas de la etiqueta registrable y del subdominio, dominios oficiales incrustados y nombres acompañados de señales de contexto como `pagos`, `acceso` o `rastreo`. Las palabras ambiguas necesitan ese contexto y una mención en la ruta o en los parámetros no atribuye el destino a una marca.
- También se señalan HTTP sin cifrar, IP literales IPv4 e IPv6, credenciales antes de `@`, caracteres codificados con `%` en el nombre de host y otros dominios aparentes al comienzo de la ruta o dentro de un subdominio. Se rechazan los formatos IPv4 ambiguos. La longitud por sí sola no genera señales.
- Los acortadores conocidos incluyen `bit.ly`, `t.co` y `tinyurl.com`. El análisis local indica que el destino queda oculto. [Bitly](https://support.bitly.com/hc/en-us/articles/230897368-How-does-a-shortened-link-work) · [X](https://help.x.com/en/using-x/url-shortener) · [TinyURL](https://tinyurl.com/)

Las observaciones del análisis local y de la inspección también pueden aparecer en sitios legítimos.

## Catálogo local de marcas

El archivo [datos_dominios/marcas.json](datos_dominios/marcas.json) registra marcas y entidades de finanzas, trámites, envíos, telecomunicaciones, cuentas globales y autenticación. Cada dominio o host incluye su fuente y el catálogo lleva una fecha de revisión. Para priorizar la cobertura colombiana se consultaron alertas de suplantación y registros sectoriales. Para la cobertura internacional se usaron informes de actividad y avisos de los proveedores. [Alertas del CSIRT de la Policía](https://cc-csirt.policia.gov.co/alertas-tips.aspx) · [Entidades vigiladas por la Superfinanciera](https://www.superfinanciera.gov.co/publicaciones/61694/industrias-supervisadasentidades-vigiladas-por-la-superintendencia-financiera-de-colombialista-general-de-entidades-vigiladas-por-la-superintendencia-financiera-de-colombia-61694/) · [Operadores postales del MinTIC](https://www.mintic.gov.co/portal/inicio/Micrositios/Informacion-general/Empresas-postales-habilitadas/) · [Informe de Check Point Research](https://blog.checkpoint.com/research/which-brands-are-impersonated-most-inside-the-q2-2026-brand-phishing-report/amp/) · [Actividad agregada de OpenPhish](https://openphish.com/phishing_activity.html)

- `dominios` reúne dominios registrables verificados. `hosts` y `autenticacion` se limitan a la coincidencia exacta del nombre de host. Así se puede documentar un portal delegado, como la autenticación de GOV.CO en `autenticaciondigital.and.gov.co`. [Ministerio TIC](https://mintic.gov.co/micrositios/rendicion-cuentas/2021/787/w3-propertyvalue-377132.html)
- `plataformas_autenticacion` identifica infraestructura compartida, como Okta, Auth0 o Microsoft Entra. En esos sufijos el informe identifica al proveedor. Atribuir un host concreto a otra organización requiere una relación exacta documentada en el catálogo. Las demás señales de la URL siguen activas. [Okta](https://developer.okta.com/docs/guides/find-your-domain/) · [Auth0](https://support.auth0.com/center/s/article/Change-the-Tenant-Domain-Name) · [Microsoft Entra](https://learn.microsoft.com/en-us/azure/active-directory-b2c/b2clogin)
- `proveedores_autenticacion` documenta qué hosts de acceso externos admite cada entidad. Durante la inspección de un recorrido HTTPS, el informe identifica el salto desde la entidad al proveedor registrado. Un enlace aislado al proveedor identifica únicamente a ese proveedor. La aplicación que solicita acceso y los permisos solicitados siguen requiriendo verificación. [Acceso a Social Security](https://www.ssa.gov/myaccount/creating-an-account.html) · [Opciones de acceso de OpenAI](https://help.openai.com/en/articles/4936824-changing-your-account-sign-in-method)
- Una mención como `noticias-bancolombia.example` recibe cero puntos. La combinación de una marca y una acción como `nequi-premios.example`, una imitación visual o un dominio oficial incrustado dentro de otro puede recibir 35. En la inspección, una relación de acceso documentada conserva las advertencias sobre el envío de contraseñas a otro origen.
- `distintivos` contiene alias que admiten comparación visual y similitud de Levenshtein a partir de 0,85. También se comprueban cambios individuales y transposiciones. La regla complementaria admite dos cambios en etiquetas principales largas o nombres distintivos con contexto. `contextuales` contiene siglas y palabras comunes que se evalúan con señales adicionales. Las pruebas verifican las referencias y el alcance de cada entrada sin hacer consultas de red.

## Reputación

- **PhishTank.** Compara la URL exacta con el CSV de URLs verificadas y activas, que la fuente publica cada hora. La comparación normaliza el host a ASCII, el puerto predeterminado y la ruta raíz. Conserva el esquema, la ruta, los parámetros y el fragmento. La actualización es manual para respetar los límites de descarga sin clave. [Documentación de PhishTank](https://phishtank.org/developer_info.php) · [Términos de PhishTank](https://phishtank.org/terms.php)
- **CERT Polska.** Compara el nombre de host con la lista de dominios activos. Un dominio listado cubre sus subdominios por etiquetas completas. Una entrada `acceso.example.com` cubre `www.acceso.example.com`, y `example.com` requiere su propia entrada. La fuente se centra en campañas dirigidas a usuarios en Polonia. [Lista de advertencias de CERT Polska](https://cert.pl/en/warning-list/)
- **Otras fuentes evaluadas.** OpenPhish Community publica una selección limitada cada 12 horas bajo términos de uso personal. El CSIRT de la Policía Nacional de Colombia publica alertas e indicadores por campaña que sirven para revisar la cobertura local. [Planes de OpenPhish](https://www.openphish.com/phishing_feeds.html) · [Términos de OpenPhish](https://openphish.com/terms.html) · [Alertas del CSIRT-PONAL](https://cc-csirt.policia.gov.co/alertas-tips)

El informe registra la fecha de consulta, la fecha de la copia y, cuando la fuente la facilita, la fecha de verificación del indicador. Las fechas se muestran en UTC. El programa considera vigentes las copias de hasta **24 horas**, calculadas desde `Last-Modified` o, cuando falta esa cabecera, desde la descarga. Este límite es una decisión del proyecto para la consulta manual. Una coincidencia vigente muestra **Alto riesgo por reputación** y aporta 70 puntos sugeridos en total aunque coincidan las dos fuentes. Una coincidencia en una copia vencida se conserva como antecedente con 0 puntos.

Si una copia falta o está vencida, una consulta sin coincidencia tiene estado `desconocido`. Si falla la lectura, tiene estado `error`. **La ausencia en una lista no confirma la legitimidad del enlace.** Durante una inspección web, el informe también muestra las coincidencias locales de los destinos anunciados por las redirecciones.

La caché de Windows se guarda en `%LOCALAPPDATA%\PhishGuard\reputacion.sqlite3`. Conserva dominios de CERT Polska y huellas SHA-256 de las URLs publicadas por PhishTank. Cada fuente se actualiza de forma independiente y un fallo conserva su última copia. El programa mantiene en memoria la consulta del usuario y omite las rutas, parámetros y fragmentos en el informe de reputación.

## DNS y RDAP

- **DNS** consulta el host exacto por HTTPS. Busca un registro A y, si hace falta, AAAA. Distingue `NXDOMAIN`, un nombre o alias sin direcciones confirmadas y una consulta incompleta o fallida. Google Public DNS recibe el nombre de host y ve la IP de la conexión. La solicitud desactiva el envío de la subred del cliente a servidores autoritativos mediante EDNS Client Subnet. [API de Google Public DNS](https://developers.google.com/speed/public-dns/docs/doh/json) · [Respuestas negativas en DNS](https://www.rfc-editor.org/rfc/rfc2308.html)
- **RDAP** consulta el dominio registrable del registro público. En una plataforma compartida como `pages.dev`, las fechas describen el dominio de la plataforma. El informe muestra fecha de registro, antigüedad en días completos, vencimiento, último cambio, registrador y estados cuando están disponibles. Las fechas se muestran en UTC. La antigüedad parte del evento `registration` publicado por el registro. [Formato de consultas RDAP](https://www.rfc-editor.org/rfc/rfc9082.html) · [Eventos y objetos RDAP](https://www.rfc-editor.org/rfc/rfc9083.html)
- **Cobertura.** La aplicación incluye la copia del [directorio de IANA](https://data.iana.org/rdap/dns.json) publicada el 20 de noviembre de 2026. Para actualizar el directorio empaquetado, reemplaza `datos_dominios/rdap_dns.json` con la copia oficial. Para `.co` y sus categorías como `.com.co` se usa el servicio HTTPS del operador colombiano cuando falta la entrada en IANA. Las redirecciones RDAP mantienen el mismo servidor HTTPS y el dominio consultado. Si falta un servicio compatible o la consulta queda incompleta, el informe indica la limitación. [Descubrimiento de servicios RDAP](https://www.rfc-editor.org/rfc/rfc9224.html) · [Delegación de .co en IANA](https://www.iana.org/domains/root/db/.co.html) · [RDAP del operador .co](https://rdap.registry.co/co/domain/nic.co)

Una consulta DNS fallida deja disponible la evidencia RDAP y viceversa. Un registro antiguo o una respuesta positiva en DNS dejan la autenticidad del enlace por confirmar.

## Desarrollo y distribución

Para abrir el programa durante el desarrollo en Windows, haz doble clic en `iniciar.cmd`. El archivo usa el Python de `.venv` cuando ese entorno existe en la carpeta del proyecto.

Desde Windows con Python 3.10 o superior y Tkinter:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m playwright install chromium
.\iniciar.cmd
.\.venv\Scripts\python.exe -m pytest -q
```

Para generar la descarga que se distribuye a los usuarios:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install pyinstaller
.\construir.ps1
```

El archivo resultante es `dist/DetectorDePhishing.exe`. Incluye Python, la interfaz, Chromium y las tablas de sufijos y Unicode para el análisis sin conexión. El usuario solo necesita el ejecutable. La compilación usa la revisión de Chromium correspondiente a la versión de Playwright instalada.

Las tablas de `datos_dominios` corresponden a la revisión del 20 de noviembre de 2026 de la Public Suffix List y a la versión 16.0.0 de la tabla de caracteres confusos de Unicode. Los archivos incluyen las licencias correspondientes. [Revisión de la PSL](https://github.com/publicsuffix/list/commit/d7d7f1fd55166aaf73ad2f526e72634490acd9c8) · [Tabla Unicode 16.0.0](https://www.unicode.org/Public/security/16.0.0/confusables.txt)

## Consola

La consola y la función `informe.generar_informe(resultado, inspeccion=None)` ofrecen el dictamen de las reglas v1. Para obtener el resumen en JSON, ejecuta `python main.py https://example.com --json`. Se puede combinar con `--dns-rdap` o `--inspeccionar`. El JSON incluye el host, los motivos, las fuentes y sus fechas, el alcance solicitado y las limitaciones. La aplicación lo imprime en la consola y mantiene el historial desactivado.

El puntaje suma una sola vez por análisis cada regla aplicable, hasta 100. Una coincidencia de reputación vigente aporta 70 puntos. Una posible suplantación de marca aporta 35. Un formulario de contraseña en esa misma página con indicios de suplantación aporta 20. Un formulario sensible con destino en otro dominio sin relación documentada aporta 20. El uso de HTTP en la página que recoge esos datos o en su receptor aporta 10. Un dominio registrado hace menos de 30 días aporta 10 si RDAP informa la fecha y el registro corresponde al dominio evaluado. La reputación también cubre los destinos anunciados durante la inspección.

Desde 40 puntos el nivel es **Sospechosa** y desde 70 es **Alto riesgo**. Por debajo de 40, un indicio o una observación técnica merece **Precaución**. Sin indicios, una comprobación pendiente da **Inconcluso**. La cobertura se refiere a las comprobaciones solicitadas. Una lista ausente o vencida mantiene la cobertura parcial incluso si otra fuente activa la alerta. Los pesos son provisionales y requieren evaluación con enlaces etiquetados antes de interpretar el rendimiento del detector.

```powershell
python main.py --actualizar-reputacion
python main.py https://example.com
python main.py https://www.nic.co --dns-rdap
python main.py https://example.com --inspeccionar
python main.py https://example.com --captura
python main.py https://example.com capturas/ejemplo.png --full
```

Una URL sola solicita análisis. `--actualizar-reputacion` se ejecuta sin URL y devuelve `1` si falla alguna fuente. `--inspeccionar` imprime el informe y usa el código de salida `1` si la inspección queda incompleta. Una ruta de salida, `--captura` o `--full` solicita también la imagen. La consola puede conservar los argumentos en su historial. Para enlaces sensibles, utiliza la ventana de escritorio.

`--dns-rdap` añade el informe de consulta externa y muestra cualquier limitación por fuente, conservando los resultados locales.

## Reutilización

- `analyzers.url_analyzer.analizar_url(texto)` devuelve el destino normalizado, las partes del dominio y señales técnicas. La dirección apta para captura puede contener parámetros privados.
- `analyzers.brand_analyzer.analizar_marca(url)` acepta una dirección o el resultado del analizador de URL. Devuelve `estado`, `puntos_sugeridos`, `marca` y `explicacion`. Una referencia oficial del catálogo recibe `ausente` y 0 puntos de suplantación. Un indicio de imitación recibe `observado` y 35 puntos sugeridos. Las señales técnicas de la dirección se evalúan por separado.
- `analyzers.reputation.analizar_reputacion(url)` devuelve las evidencias por fuente y `puntos_sugeridos`. `actualizar_listas()` descarga las listas y devuelve el resultado de cada fuente.
- `analisis.analizar(texto)` combina URL, marca y reputación para escritorio y consola. Expone la reputación en `reputacion` y el resultado de marca en `analisis_marca`. La interfaz está en `escritorio.py` y la navegación en `captura.py`.
- `analisis.analizar(texto, consultar_dominio=True)` añade `dns_rdap` al resultado. `analyzers.rdap_dns.analizar_dns_rdap(url)` devuelve solo el informe de DNS y RDAP.

`inspeccion.inspeccionar(url)` devuelve los pasos HTTP, el título, los formularios observados y el motivo si la inspección queda incompleta. `inspeccion.describir(resultado)` genera el informe de texto para escritorio y consola.
