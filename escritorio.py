"""Panel de revisión de enlaces para escritorio."""
import json
from math import cos, sin, radians

from PySide6.QtCore import QIODevice, QObject, QPoint, QPointF, QRectF, QRunnable, QSaveFile, QSettings, Qt, QThreadPool, QTimer, Signal, Slot
from PySide6.QtGui import QBrush, QColor, QFont, QFontDatabase, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QProgressBar, QPushButton, QScrollArea, QTextEdit, QVBoxLayout, QWidget,
)

from analyzers.brand_analyzer import lineas_catalogo
from analyzers.rdap_dns import lineas_dns_rdap
from analyzers.reputation import lineas_actualizacion, lineas_reputacion
from captura import imagen
from inspeccion import describir
from revision import analizar_completo


ESTILO = """
QWidget { color:#ecf1ff; font-size:15px; background:transparent; }
QWidget#base,QDialog { background:#0c1220; }
QFrame#barra { background:#10182a; border-bottom:1px solid #293248; }
QFrame#hero { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #18243c,stop:0.62 #1a2945,stop:1 #203654);
              border:1px solid #344660; border-radius:18px; }
QFrame#panel { background:#141e30; border:1px solid #2b3950; border-radius:16px; }
QLabel#marca { font-size:22px;font-weight:700; }
QLabel#titulo { font-size:32px;font-weight:700; }
QLabel#nivel { font-size:25px;font-weight:700; }
QLabel#subtitulo { font-size:17px;font-weight:600; }
QLabel#muted,QLabel#estado { color:#b3c0d6; font-size:14px; }
QLabel#kicker { color:#a4cafa;font-size:12px;font-weight:700; }
QFrame#accion { background:#202f46; border-radius:9px; }
QFrame#servicio { background:#141e30; border:1px solid #2b3950; border-radius:12px; }
QLineEdit { background:#0c1424;border:1px solid #50617c;border-radius:9px;padding:11px;color:white; }
QPushButton { padding:9px 14px;border:1px solid #3a4d68;border-radius:8px;background:#1a283f;color:#e6eeff;font-weight:600; }
QPushButton:hover {background:#283b57;}
QPushButton#principal {background:#9be8d0;color:#0c322e;border-color:#9be8d0;font-size:15px;padding:11px 20px;}
QPushButton#principal:hover {background:#c0f7e5;}
QPushButton:disabled {color:#9aaac2;background:#202e42;}
QPushButton:focus,QLineEdit:focus,QCheckBox:focus {border:2px solid #aae9ff;}
QTextEdit {background:#111a2c;border:1px solid #34445b;border-radius:8px;padding:12px;}
QCheckBox {spacing:12px;}
QScrollArea {border:0;}
QScrollBar:vertical {background:#111929;width:9px;}
QScrollBar::handle:vertical {background:#43516a;border-radius:4px;min-height:28px;}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {height:0;}
QProgressBar {border:none;background:#303f56;border-radius:3px;}
QProgressBar::chunk {background:#93dec9;border-radius:3px;}
"""


def etiqueta(texto="", nombre=""):
    widget = QLabel(texto)
    widget.setObjectName(nombre)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setWordWrap(True)
    return widget


def tarjeta(nombre="panel", margen=22):
    marco = QFrame()
    marco.setObjectName(nombre)
    caja = QVBoxLayout(marco)
    caja.setContentsMargins(margen, margen, margen, margen)
    caja.setSpacing(9)
    return marco, caja


class Escudo(QWidget):
    """Marca de la aplicación y su ilustración ampliada en la cabecera."""
    def __init__(self, grande=False):
        super().__init__()
        self.grande = grande
        self.setFixedSize(180 if grande else 32, 102 if grande else 32)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def paintEvent(self, evento):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.translate(self.width()/2, self.height()/2)
        if self.grande:
            p.scale(1, .84)
            for radio in (34, 46, 60):
                p.setPen(QPen(QColor("#405572"), 1, Qt.PenStyle.DotLine))
                p.drawEllipse(QPointF(), radio, radio)
            for radio, angulo in ((46, -38), (60, 163), (46, 93)):
                a = radians(angulo)
                p.setBrush(QColor("#9be8d0"))
                p.drawEllipse(QPointF(radio*cos(a), radio*sin(a)), 2.5, 2.5)
                p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(QColor("#46627f"), 1))
            for lado in (-1, 1):
                p.drawLine(QPointF(39*lado, 15), QPointF(58*lado, 32))
                p.drawLine(QPointF(58*lado, 32), QPointF(84*lado, 32))
                p.drawEllipse(QPointF(84*lado, 32), 2, 2)
            p.scale(2.45, 2.85)
        escudo = QPainterPath()
        escudo.moveTo(0, -13)
        escudo.lineTo(11, -9)
        escudo.lineTo(11, 0)
        escudo.quadTo(11, 8, 0, 14)
        escudo.quadTo(-11, 8, -11, 0)
        escudo.lineTo(-11, -9)
        escudo.closeSubpath()
        grad = QLinearGradient(-12, -10, 12, 12)
        grad.setColorAt(0, QColor("#b3ffe0"))
        grad.setColorAt(1, QColor("#60c7b6"))
        p.setPen(Qt.PenStyle.NoPen)
        p.fillPath(escudo, QBrush(grad))
        p.setPen(QPen(QColor("#143d3f"), 2.3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawLine(QPointF(-5, 0), QPointF(-1, 4))
        p.drawLine(QPointF(-1, 4), QPointF(6, -4))
        p.end()


class Puntaje(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedSize(108, 108)
        self.valor = 0
        self.color = "#bad2ed"

    def mostrar(self, valor, color):
        self.valor, self.color = valor, color
        self.setAccessibleName(f"Riesgo observado: {valor} de 100 puntos")
        self.update()

    def paintEvent(self, evento):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        anillo = QRectF(5, 5, 98, 98)
        p.setPen(QPen(QColor("#32415a"), 6))
        p.drawEllipse(anillo)
        p.setPen(QPen(QColor(self.color), 6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        if self.valor:
            p.drawArc(anillo, 90*16, -round(self.valor*3.6*16))
        fuente = QFont(self.font())
        fuente.setPixelSize(31)
        fuente.setBold(True)
        p.setFont(fuente)
        p.drawText(QRectF(0, 23, 108, 41), Qt.AlignmentFlag.AlignCenter, str(self.valor))
        fuente.setPixelSize(13)
        p.setFont(fuente)
        p.drawText(QRectF(0, 61, 108, 19), Qt.AlignmentFlag.AlignCenter, "de 100")
        p.end()


class Avisos(QObject):
    progreso = Signal(str)
    terminado = Signal(object, str)


class Trabajo(QRunnable):
    def __init__(self, operacion):
        super().__init__()
        self.operacion = operacion
        self.avisos = Avisos()

    def run(self):
        try:
            datos = self.operacion(self.avisos.progreso.emit)
        except ValueError as exc:
            self.avisos.terminado.emit(None, str(exc))
        except Exception:
            self.avisos.terminado.emit(None, "No se pudo completar la revisión. Inténtalo de nuevo.")
        else:
            self.avisos.terminado.emit(datos, "")


NIVELES = {
    "Alto riesgo": ("Enlace de alto riesgo", "#ff958d"),
    "Sospechosa": ("Este enlace parece sospechoso", "#ffb284"),
    "Precaución": ("Usa este enlace con precaución", "#f6d58a"),
    "Inconcluso": ("Falta información para decidir", "#becff5"),
    "Sin indicadores detectados": ("Sin señales de engaño detectadas", "#a4e4d1"),
}

def razones(revision):
    d = revision.informe
    marca = revision.resultado.analisis_marca
    nombre = marca.marca if marca and marca.puntos_sugeridos else None
    textos = {
        "reputacion": "El enlace o uno de sus destinos figura en una lista de sitios denunciados por engaño.",
        "marca": (f"La dirección se parece a la de {nombre} y está fuera de sus sitios conocidos." if nombre
                  else "Hay indicios de que el sitio intenta hacerse pasar por una marca conocida."),
        "credenciales": "La página que parece imitar a una marca también pide una contraseña.",
        "formulario_externo": "Un formulario envía información sensible a otro sitio sin relación conocida.",
        "http_sensible": "Los datos que pide la página podrían viajar sin protección.",
        "registro_reciente": "La dirección del sitio se registró hace menos de un mes.",
    }
    motivos = [textos.get(r["id"], r["motivo"]) for r in d["reglas"]]
    for observacion in revision.resultado.senales:
        if marca and observacion in marca.senales:
            continue
        if "HTTP" in observacion:
            motivos.append("La conexión con esta dirección no cifra los datos.")
        elif "acortado" in observacion:
            motivos.append("El enlace está acortado y oculta el destino a primera vista.")
        elif "IP literal" in observacion:
            motivos.append("La dirección usa números en lugar del nombre de un sitio.")
        else:
            motivos.append("La forma de escribir el enlace puede ocultar a qué sitio te lleva.")
    if not motivos and d["observaciones"]:
        motivos.append("Encontramos detalles en la dirección o en el recorrido que conviene verificar.")
    return list(dict.fromkeys(motivos))


def pendientes(revision):
    d = revision.informe
    faltan = []
    if any(not e["vigente"] for e in d["reputacion"]):
        faltan.append("comparar el enlace con todas las listas de sitios denunciados")
    if revision.inspeccion.limitacion:
        faltan.append("revisar todo el contenido de la página")
    dominio = revision.resultado.dns_rdap
    if dominio.rdap.antiguedad_dias is None:
        faltan.append("confirmar cuándo se registró el sitio")
    if dominio.dns.estado in ("desconocido", "error"):
        faltan.append("confirmar la dirección del sitio")
    if not faltan and d["limitaciones"]:
        return "Quedaron comprobaciones pendientes. Puedes consultarlas en el informe."
    return ("Quedó pendiente " + ", ".join(faltan) + ".") if faltan else ""


class Ventana(QWidget):
    def __init__(self, ajustes=None):
        super().__init__()
        self.setWindowTitle("QuimeraLink · Revisión de enlaces")
        self.setObjectName("base")
        self.setStyleSheet(ESTILO)
        self.resize(900, 790)
        self.setMinimumSize(530, 460)
        self.ajustes = ajustes if ajustes is not None else QSettings("QuimeraLink", "Escritorio")
        self.revision = None
        self.ocupado = False
        raiz = QVBoxLayout(self)
        raiz.setContentsMargins(0, 0, 0, 0)
        raiz.setSpacing(0)
        barra = QFrame()
        barra.setObjectName("barra")
        nav = QHBoxLayout(barra)
        nav.setContentsMargins(26, 12, 26, 12)
        nav.addWidget(Escudo())
        nav.addWidget(etiqueta("QuimeraLink", "marca"))
        nav.addStretch()
        self.config = QPushButton("Configuración")
        nav.addWidget(self.config)
        raiz.addWidget(barra)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        raiz.addWidget(self.scroll)
        fondo = QWidget()
        self.scroll.setWidget(fondo)
        centrar = QHBoxLayout(fondo)
        centrar.setContentsMargins(20, 20, 20, 22)
        cuerpo = QWidget()
        cuerpo.setMaximumWidth(960)
        centrar.addWidget(cuerpo)
        pagina = QVBoxLayout(cuerpo)
        pagina.setContentsMargins(0, 0, 0, 0)
        pagina.setSpacing(14)

        hero, caja = tarjeta("hero")
        fila = QHBoxLayout()
        titulos = QVBoxLayout()
        titulos.addWidget(etiqueta("REVISIÓN DE ENLACES", "kicker"))
        titulos.addWidget(etiqueta("¿Puedes confiar en este enlace?", "titulo"))
        titulos.addWidget(etiqueta("Pega la dirección para comprobar si hay señales de engaño.", "muted"))
        fila.addLayout(titulos, 1)
        self.ilustracion = Escudo(True)
        fila.addWidget(self.ilustracion)
        caja.addLayout(fila)
        entrada = QHBoxLayout()
        self.entrada = QLineEdit()
        self.entrada.setAccessibleName("Dirección del enlace")
        self.entrada.setPlaceholderText("https://ejemplo.com")
        self.entrada.setClearButtonEnabled(True)
        self.analizar = QPushButton("Analizar enlace")
        self.analizar.setObjectName("principal")
        entrada.addWidget(self.entrada, 1)
        entrada.addWidget(self.analizar)
        caja.addLayout(entrada)
        caja.addWidget(etiqueta("Al analizar, se consulta el nombre del sitio y se visita la página desde tu conexión.", "muted"))
        self.barra = QProgressBar()
        self.barra.setRange(0, 0)
        self.barra.setTextVisible(False)
        self.barra.setFixedHeight(4)
        caja.addWidget(self.barra)
        self.estado = etiqueta("", "estado")
        caja.addWidget(self.estado)
        pagina.addWidget(hero)

        self.inicio = QWidget()
        caja = QVBoxLayout(self.inicio)
        caja.setContentsMargins(0, 5, 0, 0)
        caja.addWidget(etiqueta("Qué comprobaremos", "subtitulo"))
        servicios = QHBoxLayout()
        for titulo, desc, tono in (("Identidad", "¿Intenta hacerse pasar por una marca conocida?", "#a6caff"),
                                   ("Denuncias", "¿Ya se ha denunciado esta dirección por engaño?", "#e9c098"),
                                   ("Contenido", "¿Adónde te lleva y qué datos te pide?", "#99e6cd")):
            servicio, contenido = tarjeta("servicio", 15)
            clave = etiqueta(titulo, "subtitulo")
            clave.setStyleSheet(f"color:{tono}")
            contenido.addWidget(clave)
            contenido.addWidget(etiqueta(desc, "muted"))
            contenido.addStretch()
            servicios.addWidget(servicio, 1)
        caja.addLayout(servicios)
        pagina.addWidget(self.inicio)
        self.panel, caja = tarjeta()
        fila = QHBoxLayout()
        self.puntos = Puntaje()
        fila.addWidget(self.puntos)
        fila.addSpacing(12)
        cab = QVBoxLayout()
        cab.addWidget(etiqueta("RIESGO OBSERVADO", "kicker"))
        self.nivel = etiqueta("", "nivel")
        self.host = etiqueta("", "muted")
        cab.addWidget(self.nivel)
        cab.addWidget(self.host)
        fila.addLayout(cab, 1)
        caja.addLayout(fila)
        accion, recomendacion = tarjeta("accion", 12)
        recomendacion.addWidget(etiqueta("Qué hacer", "kicker"))
        self.consejo = etiqueta("", "subtitulo")
        recomendacion.addWidget(self.consejo)
        caja.addWidget(accion)
        self.motivos = etiqueta()
        caja.addWidget(self.motivos)
        self.pendiente = etiqueta("", "muted")
        caja.addWidget(self.pendiente)
        self.foto = QLabel()
        self.foto.setAlignment(Qt.AlignmentFlag.AlignCenter)
        caja.addWidget(self.foto)
        self.nota_foto = etiqueta("", "muted")
        caja.addWidget(self.nota_foto)
        self.detalle = QPushButton("Ver informe detallado")
        caja.addWidget(self.detalle, 0, Qt.AlignmentFlag.AlignLeft)
        pagina.addWidget(self.panel)
        pagina.addStretch()
        self.entrada.textChanged.connect(self.limpiar)
        self.entrada.returnPressed.connect(self.revisar)
        self.analizar.clicked.connect(self.revisar)
        self.config.clicked.connect(self.configurar)
        self.detalle.clicked.connect(self.mostrar_informe)
        self.limpiar()
        self.entrada.setFocus()

    def resizeEvent(self, evento):
        self.ilustracion.setVisible(self.width() >= 700)
        super().resizeEvent(evento)

    def limpiar(self):
        self.revision = None
        self.panel.hide()
        self.inicio.show()
        self.estado.clear()
        self.estado.hide()
        self.barra.hide()
        self.foto.clear()
        self.foto.hide()
        self.nota_foto.hide()

    def configurar(self):
        dialogo = QDialog(self)
        dialogo.setWindowTitle("Configuración")
        caja = QVBoxLayout(dialogo)
        caja.setContentsMargins(22, 20, 22, 20)
        caja.addWidget(etiqueta("Configuración", "nivel"))
        opcion = QCheckBox("Incluir una captura de la página")
        opcion.setChecked(self.ajustes.value("captura", False, type=bool))
        caja.addWidget(opcion)
        caja.addWidget(etiqueta("Hace una visita adicional para mostrar una imagen del enlace original. "
                                "La imagen se mantiene en memoria.", "muted"))
        opcion.toggled.connect(lambda valor: self.ajustes.setValue("captura", valor))
        listo = QPushButton("Listo")
        listo.clicked.connect(dialogo.accept)
        caja.addWidget(listo, 0, Qt.AlignmentFlag.AlignRight)
        dialogo.resize(410, 180)
        dialogo.exec()

    def revisar(self):
        if self.ocupado:
            return
        self.limpiar()
        enlace = self.entrada.text().strip()
        self.estado.show()
        if not enlace:
            self.estado.setText("Pega un enlace para empezar.")
            self.entrada.setFocus()
            return
        self.inicio.hide()
        self.ocupado = True
        self.barra.show()
        self.estado.setText("Iniciando la revisión…")
        self.entrada.setEnabled(False)
        self.analizar.setEnabled(False)
        self.config.setEnabled(False)
        self.analizar.setText("Analizando…")
        self._trabajo(lambda progreso: analizar_completo(enlace, progreso), self.recibir)

    def _trabajo(self, operacion, recibir):
        trabajo = Trabajo(operacion)
        trabajo.avisos.progreso.connect(self.estado.setText, Qt.ConnectionType.QueuedConnection)
        trabajo.avisos.terminado.connect(recibir, Qt.ConnectionType.QueuedConnection)
        QThreadPool.globalInstance().start(trabajo)

    def terminar(self):
        self.ocupado = False
        self.barra.hide()
        self.entrada.setEnabled(True)
        self.analizar.setEnabled(True)
        self.config.setEnabled(True)
        self.analizar.setText("Analizar enlace")

    @Slot(object, str)
    def recibir(self, revision, error):
        if error:
            self.terminar()
            self.inicio.show()
            self.estado.setText(error)
            return
        self.revision = revision
        self.inicio.hide()
        d = revision.informe
        titulo, color = NIVELES[d["nivel"]]
        self.nivel.setText(titulo)
        self.nivel.setStyleSheet(f"color:{color};")
        self.host.setText(d["dominio"])
        self.puntos.mostrar(d["puntos"], color)
        if d["nivel"] in ("Alto riesgo", "Sospechosa", "Precaución"):
            self.consejo.setText("Evita escribir tus datos aquí. Abre la aplicación oficial o escribe tú la dirección que conoces.")
        elif d["nivel"] == "Inconcluso":
            self.consejo.setText("Antes de continuar, confirma el enlace con quien te lo envió por otro medio.")
        else:
            self.consejo.setText("Comprueba que reconoces la dirección antes de compartir información personal.")
        motivos = razones(revision)
        if aviso := d["disponibilidad"]:
            motivos.append(aviso["mensaje"])
        self.motivos.setText("\n".join("•  " + t for t in motivos))
        self.motivos.setVisible(bool(motivos))
        nota = pendientes(revision)
        self.pendiente.setText(nota)
        self.pendiente.setVisible(bool(nota))
        self.panel.show()
        QTimer.singleShot(0, self.enfocar_resultado)
        if self.ajustes.value("captura", False, type=bool):
            destino = revision.resultado.url_captura
            if destino:
                self.estado.setText("Resultado listo. Preparando la captura opcional…")
                self._trabajo(lambda _: imagen(destino), self.recibir_foto)
                return
            self.nota_foto.setText("La captura requiere una dirección pública sin credenciales.")
            self.nota_foto.show()
        self.estado.hide()
        self.terminar()

    def enfocar_resultado(self):
        if self.panel.isVisible():
            alto = self.scroll.viewport().height()
            inicio = self.panel.mapTo(self.scroll.widget(), QPoint()).y()
            barra = self.scroll.verticalScrollBar()
            if inicio + min(self.panel.height(), 215) > barra.value() + alto:
                barra.setValue(inicio - 12)

    @Slot(object, str)
    def recibir_foto(self, datos, error):
        foto = QPixmap()
        if datos and foto.loadFromData(datos, "PNG"):
            self.foto.setPixmap(foto.scaled(400, 195, Qt.AspectRatioMode.KeepAspectRatio,
                                             Qt.TransformationMode.SmoothTransformation))
            self.foto.show()
            self.nota_foto.setText("Captura del enlace original")
        else:
            self.nota_foto.setText("No se pudo obtener la captura opcional.")
        self.nota_foto.show()
        self.estado.hide()
        self.terminar()

    def mostrar_informe(self):
        revision = self.revision
        r, d = revision.resultado, revision.informe
        lineas = [r.dominio, f"{d['nivel']} · {d['puntos']}/100 · Cobertura {d['cobertura']}",
                  d["recomendacion"], "", "Señales y puntuación"]
        lineas.extend(f"+{regla['puntos']} · {regla['motivo']}" for regla in d["reglas"])
        lineas.extend(d["observaciones"] or ["Sin observaciones adicionales."])
        lineas.extend(["", "Limitaciones", *(d["limitaciones"] or ["Ninguna en las comprobaciones realizadas."])])
        if r.dominio_registrable:
            lineas.append("Dominio registrable · " + r.dominio_registrable)
        if r.dominio_unicode:
            lineas.append("Nombre internacional · " + r.dominio_unicode)
        lineas.extend(lineas_catalogo(r.coincidencias_marca))
        lineas.extend(["", "Reputación", *lineas_actualizacion(revision.actualizaciones), *lineas_reputacion(r.reputacion)])
        if r.dns_sistema:
            lineas.extend(["", "DNS del sistema", r.dns_sistema.explicacion])
        lineas.extend(["", *lineas_dns_rdap(r.dns_rdap), "", describir(revision.inspeccion)])
        dialogo = QDialog(self)
        dialogo.setWindowTitle("Informe detallado · QuimeraLink")
        caja = QVBoxLayout(dialogo)
        caja.addWidget(etiqueta("Informe detallado", "nivel"))
        texto = QTextEdit()
        texto.setReadOnly(True)
        texto.setPlainText("\n".join(lineas))
        caja.addWidget(texto)
        guardar = QPushButton("Guardar dictamen JSON")
        guardar.clicked.connect(self.guardar)
        caja.addWidget(guardar, 0, Qt.AlignmentFlag.AlignRight)
        dialogo.resize(min(self.width(), 720), min(self.height(), 620))
        dialogo.exec()

    def guardar(self):
        ruta, _ = QFileDialog.getSaveFileName(self, "Guardar dictamen", "dictamen.json", "Informe JSON (*.json)")
        if ruta:
            archivo = QSaveFile(ruta)
            datos = json.dumps(self.revision.informe, ensure_ascii=False, indent=2).encode("utf-8")
            if not archivo.open(QIODevice.OpenModeFlag.WriteOnly) or archivo.write(datos) != len(datos) or not archivo.commit():
                QMessageBox.warning(self, "Guardar dictamen", "No se pudo guardar el informe.")


def abrir():
    app = QApplication.instance() or QApplication([])
    app.setStyle("Fusion")
    app.setFont(QFont("Inter" if "Inter" in QFontDatabase.families() else "Segoe UI", 10))
    ventana = Ventana()
    ventana.show()
    app.exec()
