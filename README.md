# Detector de phishing · v1.2 para Windows

Abre el ejecutable **DetectorDePhishing.exe**, pega un enlace y pulsa **Analizar enlace**. El programa muestra el nombre de host de destino, el dominio registrable cuando existe y las señales encontradas. Revisa la dirección en tu equipo sin abrirla, enviarla a un servicio ni guardar un historial. Un resultado sin señales deja la autenticidad del sitio sin confirmar.

**Inspeccionar página** visita el enlace desde tu conexión. Muestra los orígenes y estados HTTP del recorrido, el origen final, su dominio registrable, el título y los destinos declarados por los formularios del HTML estático. Sigue hasta cinco redirecciones y valida cada salto antes de conectarse. Señala los cambios de dominio registrable y los saltos de HTTPS a HTTP, así como los formularios con campos de contraseña que apuntan a otro origen o a una dirección HTTP. Si el recorrido se interrumpe, identifica el último origen que respondió e indica el destino anunciado cuando el servidor lo proporcionó en una redirección válida. La inspección usa solicitudes GET, sin ejecutar JavaScript, cargar recursos de la página ni enviar formularios.

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
- `distintivos` contiene alias que admiten comparación visual y similitud de Levenshtein a partir de 0,85. También se comprueban cambios individuales y transposiciones. La regla complementaria admite dos cambios en etiquetas principales largas o nombres distintivos con contexto. `contextuales` contiene siglas y palabras comunes que se evalúan con señales adicionales. Las pruebas verifican las referencias y el alcance de cada entrada sin hacer consultas de red.

### Fuentes de reputación evaluadas

- **OpenPhish Community Feed.** Publica una selección limitada de URLs cada 12 horas. Sus términos exigen consentimiento escrito para uso comercial. [Planes de OpenPhish](https://www.openphish.com/phishing_feeds.html) · [Términos de uso](https://www.openphish.com/terms.html)
- **PhishTank.** Ofrece descargas de URLs verificadas por la comunidad con actualización horaria y una API con límites de consultas. Una copia local sería una opción para añadir señales de reputación en el futuro. [Documentación de PhishTank](https://phishtank.org/developer_info.php)

El motor actual carga sólo el catálogo local. Una futura integración de reputación aportaría evidencia sobre URLs observadas y conservaría los resultados de las reglas locales cuando el servicio externo no esté disponible.

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

```powershell
python main.py https://example.com
python main.py https://example.com --inspeccionar
python main.py https://example.com --captura
python main.py https://example.com capturas/ejemplo.png --full
```

Una URL sola solicita análisis. `--inspeccionar` imprime el informe y usa el código de salida `1` si la inspección queda incompleta. Una ruta de salida, `--captura` o `--full` solicita también la imagen. La consola puede conservar los argumentos en su historial. Para enlaces sensibles, utiliza la ventana de escritorio.

## Reutilización

- `analyzers.url_analyzer.analizar_url(texto)` devuelve el destino normalizado, las partes del dominio y señales técnicas. La dirección apta para captura puede contener parámetros privados.
- `analyzers.brand_analyzer.analizar_marca(url)` acepta una dirección o el resultado del analizador de URL. Devuelve `estado`, `puntos_sugeridos`, `marca` y `explicacion`. Una referencia oficial del catálogo recibe `ausente` y 0 puntos de suplantación. Un indicio de imitación recibe `observado` y 35 puntos sugeridos. Las señales técnicas de la dirección se evalúan por separado.
- `analisis.analizar(texto)` combina ambos resultados para escritorio y consola y expone el resultado de marca en `analisis_marca`. La interfaz está en `escritorio.py` y la navegación en `captura.py`.

`inspeccion.inspeccionar(url)` devuelve los pasos HTTP, el título, los formularios observados y el motivo si la inspección queda incompleta. `inspeccion.describir(resultado)` genera el informe de texto para escritorio y consola.
