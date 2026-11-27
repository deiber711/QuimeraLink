"""Dictamen versionado y serializable para la consola y el escritorio."""
from urllib.parse import urlsplit

from analisis import Resultado
from analyzers.brand_analyzer import cliente_de_proveedor
from analyzers.reputation import FUENTES
from dominios import dominio_registrable
from inspeccion import Inspeccion, senales_redirecciones


_MENSAJES_DISPONIBILIDAD = {
    "nxdomain": "El sitio probablemente no existe.",
    "sin_direccion": "El sitio no tiene una dirección DNS confirmada.",
    "pagina_no_encontrada": "La página no se encontró en el sitio.",
    "inaccesible": "No se pudo acceder a la página.",
    "desconocido": "No se pudo comprobar la disponibilidad del sitio.",
}


def _disponibilidad(resultado, inspeccion):
    if inspeccion and inspeccion.pasos:
        paso = inspeccion.pasos[-1]
        host = urlsplit(paso.origen).hostname
        if paso.estado in (404, 410):
            return "pagina_no_encontrada", host, f"{paso.origen} respondió con HTTP {paso.estado}."
        if paso.estado is not None and 400 <= paso.estado < 600:
            return "inaccesible", host, f"{paso.origen} respondió con HTTP {paso.estado}."
        if inspeccion.fallo_acceso:
            return inspeccion.fallo_acceso, host, inspeccion.limitacion
        if any(p.estado is not None for p in inspeccion.pasos):
            return None

    dns_externo = resultado.dns_rdap.dns if resultado.dns_rdap else None
    dns = dns_externo if dns_externo and dns_externo.estado not in ("desconocido", "error") else (
        resultado.dns_sistema or dns_externo
    )
    if dns and dns.estado != "resuelve":
        estado = "desconocido" if dns.estado == "error" else dns.estado
        detalle = f"DNS · {dns.explicacion}" if dns is dns_externo else dns.explicacion
        return estado, dns.host, detalle
    return None


def _reglas_formularios(inspeccion, marca_final):
    if not inspeccion.formularios or not inspeccion.pasos:
        return
    pagina = urlsplit(inspeccion.pasos[-1].origen)
    registrable = dominio_registrable(pagina.hostname)
    sensibles = [f for f in inspeccion.formularios if f.tiene_password or f.datos_financieros]
    if marca_final and any(f.tiene_password for f in sensibles):
        yield "credenciales", 20, "La página con indicios de suplantación solicita una contraseña."
    destinos = {urlsplit(o) for f in sensibles for o in (f.origen, *f.destinos_botones) if o}
    if sensibles and (pagina.scheme == "http" or any(o.scheme == "http" for o in destinos)):
        yield "http_sensible", 10, "La página o el destino del formulario sensible usa HTTP."
    for destino in destinos:
        if destino.hostname == pagina.hostname or (
            registrable and dominio_registrable(destino.hostname) == registrable
        ):
            continue
        if (pagina.scheme == destino.scheme == "https" and pagina.port is None and destino.port is None
                and cliente_de_proveedor(pagina.hostname, registrable, destino.hostname)):
            continue
        yield "formulario_externo", 20, "Un formulario sensible apunta fuera del dominio sin relación documentada."
        break


def generar_informe(resultado: Resultado, inspeccion: Inspeccion | None = None) -> dict:
    """Resume las comprobaciones solicitadas sin serializar la URL ni el texto del sitio."""
    reglas = []
    limitaciones = []
    fuentes = []
    observaciones = list(resultado.senales)
    marca = resultado.analisis_marca
    marca_final = bool(marca and marca.puntos_sugeridos)
    marca_observada = marca_final
    consultas = [(resultado.dominio, resultado.reputacion)]
    if inspeccion:
        observaciones.extend(senales_redirecciones(inspeccion.pasos))
        for paso in inspeccion.pasos:
            if paso.origen_redireccion:
                marca_final = bool(paso.puntos_marca_destino)
                marca_observada |= marca_final
                if paso.reputacion_destino is not None:
                    consultas.append((urlsplit(paso.origen_redireccion).hostname, paso.reputacion_destino))
        marca_final |= bool(inspeccion.senales_contenido)
        marca_observada |= marca_final
        observaciones.extend(inspeccion.senales_contenido)
        if inspeccion.limitacion:
            limitaciones.append(inspeccion.limitacion)
        for f in inspeccion.formularios or ():
            if f.tiene_password or f.datos_financieros:
                receptores = (f.origen, *f.destinos_botones)
                if None in receptores:
                    limitaciones.append("Destino de formulario sensible sin identificar.")
                if any(o and o != inspeccion.pasos[-1].origen for o in receptores):
                    observaciones.append("Un formulario sensible declara otro origen de envío.")
    for host, rep in consultas:
        for e in rep.evidencias:
            fuentes.append(dict(host=host, fuente=e.fuente.nombre, estado=e.estado, vigente=e.vigente,
                                consulta=e.fecha_consulta.isoformat(), detalle=e.explicacion,
                                fecha_lista=e.fecha_lista.isoformat() if e.fecha_lista else None,
                                fecha_indicador=e.fecha_indicador.isoformat() if e.fecha_indicador else None))
        disponibles = {e.fuente for e in rep.evidencias if e.vigente and e.estado in ("observado", "ausente")}
        for fuente in FUENTES:
            if fuente not in disponibles:
                limitaciones.append(f"{host} · {fuente.nombre} sin comprobación vigente.")
    if any(rep.puntos_sugeridos for _, rep in consultas):
        reglas.append(("reputacion", 70, "Alto riesgo por reputación. Coincidencia vigente en una lista de phishing."))
    if marca_observada:
        reglas.append(("marca", 35, "Indicios de suplantación de marca en el enlace o la página."))
    dominio = resultado.dns_rdap
    if dominio:
        for fuente, consulta in (("DNS", dominio.dns), ("RDAP", dominio.rdap)):
            if consulta.estado in ("error", "desconocido"):
                limitaciones.append(f"{fuente} · {consulta.explicacion}")
        edad = dominio.rdap.antiguedad_dias
        if edad is None and dominio.rdap.estado in ("observado", "ausente"):
            limitaciones.append("RDAP no aportó la antigüedad del dominio.")
        if (dominio.rdap.estado == "observado" and not dominio.registro_de_plataforma
                and edad is not None and 0 <= edad < 30):
            reglas.append(("registro_reciente", 10, f"El dominio fue registrado hace {edad} días."))
    if inspeccion:
        reglas.extend(_reglas_formularios(inspeccion, marca_final))
    disponibilidad = None
    if problema := _disponibilidad(resultado, inspeccion):
        estado, host, detalle = problema
        disponibilidad = dict(estado=estado, host=host, mensaje=_MENSAJES_DISPONIBILIDAD[estado], detalle=detalle)
        if detalle:
            limitaciones.append(detalle)
    puntos = min(100, sum(p for _, p, _ in reglas))
    if puntos >= 70:
        nivel = "Alto riesgo"
    elif puntos >= 40:
        nivel = "Sospechosa"
    elif puntos or observaciones:
        nivel = "Precaución"
    elif limitaciones:
        nivel = "Inconcluso"
    else:
        nivel = "Sin indicadores detectados"
    return dict(version_reglas=1, dominio=resultado.dominio, puntos=puntos, nivel=nivel,
                cobertura="parcial" if limitaciones else "completa para el modo solicitado",
                disponibilidad=disponibilidad,
                dns_rdap_solicitado=dominio is not None, inspeccion_solicitada=inspeccion is not None,
                dns_rdap=(dict(dns=dominio.dns.estado, rdap=dominio.rdap.estado,
                               antiguedad_dias=dominio.rdap.antiguedad_dias,
                               registro_de_plataforma=dominio.registro_de_plataforma) if dominio else None),
                reglas=[dict(id=i, puntos=p, motivo=m) for i, p, m in reglas],
                observaciones=list(dict.fromkeys(observaciones)), reputacion=fuentes,
                limitaciones=list(dict.fromkeys(limitaciones)),
                recomendacion=("Evita ingresar datos y abre el servicio por un canal oficial."
                               if reglas or observaciones else "Verifica el destino antes de ingresar datos."))
