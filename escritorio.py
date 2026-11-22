from base64 import b64encode
from queue import Empty, Queue
from threading import Thread
import tkinter as tk
from tkinter import ttk

from analisis import analizar
from analyzers.brand_analyzer import lineas_catalogo
from captura import imagen
from inspeccion import describir, inspeccionar


def abrir():
    raiz = tk.Tk()
    raiz.title("Detector de phishing")
    raiz.geometry("720x510")
    raiz.minsize(550, 450)
    raiz.configure(bg="#eef3f3")
    marco = tk.Frame(raiz, bg="white", padx=30, pady=24)
    marco.pack(fill="both", expand=True, padx=16, pady=16)

    def texto(valor, tam=11, color="#334b52", negrita=False):
        etiqueta = tk.Label(marco, text=valor, anchor="w", justify="left", bg="white", fg=color,
                            font=("Segoe UI", tam, "bold" if negrita else "normal"), wraplength=570)
        etiqueta.pack(fill="x", pady=(0, 8))
        etiqueta.bind("<Configure>", lambda evento: evento.widget.configure(wraplength=evento.width))
        return etiqueta

    texto("Revisar un enlace", 22, "#164d49", True)
    texto("Pega la dirección para revisarla en tu equipo sin visitar la página.")
    entrada = ttk.Entry(marco, font=("Segoe UI", 12))
    entrada.pack(fill="x", ipady=5)
    acciones = ttk.Frame(marco)
    acciones.pack(anchor="w", pady=14)
    dominio = texto("", 12, negrita=True)
    identidad = texto("", 10)
    aviso = texto("")
    marco_detalle = tk.Frame(marco, bg="white")
    marco_detalle.pack(fill="both", expand=True, pady=(0, 8))
    detalle = tk.Text(marco_detalle, wrap="word", height=6, bg="white", fg="#334b52",
                      font=("Segoe UI", 11), relief="flat", state="disabled")
    barra_detalle = ttk.Scrollbar(marco_detalle, orient="vertical", command=detalle.yview)
    detalle.configure(yscrollcommand=barra_detalle.set)
    barra_detalle.pack(side="right", fill="y")
    detalle.pack(side="left", fill="both", expand=True)
    estado = texto("", 10)
    destino = None
    ocupado = False
    cola = Queue()

    def mostrar_detalle(valor):
        detalle.configure(state="normal")
        detalle.delete("1.0", "end")
        detalle.insert("1.0", valor)
        detalle.configure(state="disabled")

    def limpiar(*_):
        nonlocal destino
        destino = None
        for control in (captura, inspeccion):
            control.state(["disabled"])
        for etiqueta in (dominio, identidad, aviso, estado):
            etiqueta.configure(text="")
        mostrar_detalle("")

    def revisar(*_):
        nonlocal destino
        if ocupado:
            return
        limpiar()
        try:
            resultado = analizar(entrada.get())
        except ValueError as exc:
            aviso.configure(text=str(exc))
            return
        dominio.configure(text="Destino · " + resultado.dominio)
        lineas = []
        if resultado.dominio_registrable:
            lineas.append("Dominio registrable · " + resultado.dominio_registrable)
        if resultado.dominio_unicode:
            lineas.append("Nombre internacional (Unicode) · " + resultado.dominio_unicode)
        lineas.extend(lineas_catalogo(resultado.coincidencias_marca))
        identidad.configure(text="\n".join(lineas))
        if resultado.senales:
            aviso.configure(text="Revisa estas señales antes de continuar", fg="#854805")
            mostrar_detalle("\n".join("• " + s for s in resultado.senales) +
                            "\n\nEvita ingresar datos personales. Verifica el enlace por un canal oficial.")
        else:
            aviso.configure(text="Autenticidad sin confirmar", fg="#334b52")
            mostrar_detalle("El análisis local revisó la dirección. El contenido de la página todavía no se ha inspeccionado.")
        destino = resultado.url_captura
        if destino:
            for control in (captura, inspeccion):
                control.state(["!disabled"])
            estado.configure(text="Inspeccionar página y Ver captura visitan el sitio desde tu conexión.")
        else:
            estado.configure(text="Las opciones web requieren una dirección pública sin credenciales.")

    def recibir(mostrar, error):
        nonlocal ocupado
        try:
            datos = cola.get_nowait()
        except Empty:
            raiz.after(100, recibir, mostrar, error)
            return
        ocupado = False
        for control in (entrada, boton, captura, inspeccion):
            control.state(["!disabled"])
        if datos is None:
            estado.configure(text=error)
        else:
            mostrar(datos)

    def mostrar_captura(datos):
        ventana = tk.Toplevel(raiz)
        ventana.title("Captura de " + url_dominio())
        foto = tk.PhotoImage(data=b64encode(datos))
        if foto.width() > raiz.winfo_screenwidth() or foto.height() + 80 > raiz.winfo_screenheight():
            foto = foto.subsample(2)
        vista = ttk.Label(ventana, image=foto)
        vista.image = foto
        vista.pack()
        estado.configure(text="Captura estática. Cierra la ventana para descartarla.")

    def url_dominio():
        return dominio.cget("text").removeprefix("Destino · ")

    def mostrar_inspeccion(resultado):
        ventana = tk.Toplevel(raiz)
        ventana.title("Inspección de " + url_dominio())
        ventana.geometry("640x480")
        ventana.minsize(440, 280)
        informe = tk.Text(ventana, wrap="word", padx=18, pady=14, font=("Segoe UI", 11))
        barra = ttk.Scrollbar(ventana, orient="vertical", command=informe.yview)
        informe.configure(yscrollcommand=barra.set)
        barra.pack(side="right", fill="y")
        informe.pack(side="left", fill="both", expand=True)
        informe.insert("1.0", describir(resultado))
        informe.configure(state="disabled")
        resumen = "Inspección incompleta. Consulta el informe." if resultado.limitacion else "Inspección terminada."
        estado.configure(text=resumen)

    def solicitar(operacion, mostrar, progreso, error):
        nonlocal ocupado
        if not destino or ocupado:
            return
        url = destino
        ocupado = True
        for control in (entrada, captura, inspeccion, boton):
            control.state(["disabled"])
        estado.configure(text=progreso)

        def trabajo():
            try:
                cola.put(operacion(url))
            except Exception:
                cola.put(None)

        Thread(target=trabajo).start()
        raiz.after(100, recibir, mostrar, error)

    def solicitar_captura():
        solicitar(imagen, mostrar_captura, "Obteniendo la imagen…", "No se pudo obtener la captura.")

    def solicitar_inspeccion():
        solicitar(inspeccionar, mostrar_inspeccion, "Inspeccionando la página desde tu conexión…",
                  "No se pudo obtener el informe de inspección.")

    valor = tk.StringVar()
    entrada.configure(textvariable=valor)
    valor.trace_add("write", limpiar)
    boton = ttk.Button(acciones, text="Analizar enlace", command=revisar)
    boton.pack(side="left")
    inspeccion = ttk.Button(acciones, text="Inspeccionar página", command=solicitar_inspeccion, state="disabled")
    inspeccion.pack(side="left", padx=10)
    captura = ttk.Button(acciones, text="Ver captura", command=solicitar_captura, state="disabled")
    captura.pack(side="left")
    entrada.bind("<Return>", revisar)
    entrada.focus_set()
    raiz.mainloop()
