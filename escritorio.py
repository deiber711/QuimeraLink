from base64 import b64encode
from queue import Empty, Queue
from threading import Thread
import tkinter as tk
from tkinter import messagebox, ttk

from analisis import analizar
from analyzers.brand_analyzer import lineas_catalogo
from analyzers.rdap_dns import lineas_dns_rdap
from analyzers.reputation import actualizar_listas, lineas_actualizacion, lineas_reputacion
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
    revisado = False
    ocupado = False
    cola = Queue()

    def mostrar_detalle(valor):
        detalle.configure(state="normal")
        detalle.delete("1.0", "end")
        detalle.insert("1.0", valor)
        detalle.configure(state="disabled")

    def limpiar(*_):
        nonlocal destino, revisado
        destino = None
        revisado = False
        for control in (captura, inspeccion, dns_rdap):
            control.state(["disabled"])
        for etiqueta in (dominio, identidad, aviso, estado):
            etiqueta.configure(text="")
        mostrar_detalle("")

    def revisar(*_):
        if ocupado:
            return
        limpiar()
        try:
            resultado = analizar(entrada.get())
        except ValueError as exc:
            aviso.configure(text=str(exc))
            return
        presentar(resultado)

    def presentar(resultado):
        nonlocal destino, revisado
        revisado = True
        dns_rdap.state(["!disabled"])
        dominio.configure(text="Destino · " + resultado.dominio)
        lineas = []
        if resultado.dominio_registrable:
            lineas.append("Dominio registrable · " + resultado.dominio_registrable)
        if resultado.dominio_unicode:
            lineas.append("Nombre internacional (Unicode) · " + resultado.dominio_unicode)
        lineas.extend(lineas_catalogo(resultado.coincidencias_marca))
        identidad.configure(text="\n".join(lineas))
        alto_riesgo = bool(resultado.reputacion.puntos_sugeridos)
        if alto_riesgo or resultado.senales:
            titulo = "Alto riesgo por reputación" if alto_riesgo else "Revisa estas señales antes de continuar"
            aviso.configure(text=titulo, fg="#854805")
        else:
            aviso.configure(text="Autenticidad sin confirmar", fg="#334b52")
        detalle_analisis = ["• " + s for s in resultado.senales]
        if detalle_analisis:
            detalle_analisis.append("")
        detalle_analisis.extend(("Reputación", *lineas_reputacion(resultado.reputacion)))
        if alto_riesgo or resultado.senales:
            detalle_analisis.extend(("", "Evita ingresar datos personales. Verifica el enlace por un canal oficial."))
        if resultado.dns_rdap:
            detalle_analisis[:0] = [*lineas_dns_rdap(resultado.dns_rdap), ""]
        mostrar_detalle("\n".join(detalle_analisis))
        destino = resultado.url_captura
        if destino:
            for control in (captura, inspeccion):
                control.state(["!disabled"])
            estado.configure(text="DNS/RDAP comparte solo nombres de dominio con Google Public DNS y el registro. "
                                 "Inspeccionar página y Ver captura visitan el sitio.")
        else:
            estado.configure(text="DNS/RDAP comparte solo nombres de dominio con Google Public DNS y el registro. "
                                 "La visita requiere una dirección pública sin credenciales.")

    def recibir(mostrar, error):
        nonlocal ocupado
        try:
            datos = cola.get_nowait()
        except Empty:
            raiz.after(100, recibir, mostrar, error)
            return
        ocupado = False
        for control in (entrada, boton, actualizar):
            control.state(["!disabled"])
        if revisado:
            dns_rdap.state(["!disabled"])
        if destino:
            for control in (captura, inspeccion):
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

    def solicitar(operacion, mostrar, progreso, error, *argumentos):
        nonlocal ocupado
        if ocupado:
            return
        ocupado = True
        for control in (entrada, captura, inspeccion, boton, actualizar, dns_rdap):
            control.state(["disabled"])
        estado.configure(text=progreso)

        def trabajo():
            try:
                cola.put(operacion(*argumentos))
            except Exception:
                cola.put(None)

        Thread(target=trabajo).start()
        raiz.after(100, recibir, mostrar, error)

    def solicitar_captura():
        if destino:
            solicitar(imagen, mostrar_captura, "Obteniendo la imagen…", "No se pudo obtener la captura.", destino)

    def solicitar_inspeccion():
        if destino:
            solicitar(inspeccionar, mostrar_inspeccion, "Inspeccionando la página desde tu conexión…",
                      "No se pudo obtener el informe de inspección.", destino)

    def solicitar_dns_rdap():
        if revisado:
            solicitar(lambda enlace: analizar(enlace, consultar_dominio=True), presentar,
                      "Consultando DNS y el registro del dominio…", "No se pudo completar la consulta DNS/RDAP.",
                      entrada.get())

    def mostrar_actualizacion(resultados):
        if revisado:
            revisar()
        else:
            estado.configure(text="")
        informe = "\n".join(lineas_actualizacion(resultados))
        if any(r.error for r in resultados):
            messagebox.showwarning("Actualización incompleta", informe, parent=raiz)
        else:
            messagebox.showinfo("Listas actualizadas", informe, parent=raiz)

    def actualizar_reputacion():
        solicitar(actualizar_listas, mostrar_actualizacion,
                  "Descargando las listas de PhishTank y CERT Polska…",
                  "No se pudieron actualizar las listas de reputación.")

    valor = tk.StringVar()
    entrada.configure(textvariable=valor)
    valor.trace_add("write", limpiar)
    boton = ttk.Button(acciones, text="Analizar enlace", command=revisar)
    boton.pack(side="left")
    inspeccion = ttk.Button(acciones, text="Inspeccionar página", command=solicitar_inspeccion, state="disabled")
    inspeccion.pack(side="left", padx=10)
    captura = ttk.Button(acciones, text="Ver captura", command=solicitar_captura, state="disabled")
    captura.pack(side="left")
    servicios = ttk.Frame(marco)
    servicios.pack(anchor="w")
    dns_rdap = ttk.Button(servicios, text="Consultar DNS/RDAP", command=solicitar_dns_rdap, state="disabled")
    dns_rdap.pack(side="left", padx=(0, 10))
    actualizar = ttk.Button(servicios, text="Actualizar listas de reputación", command=actualizar_reputacion)
    actualizar.pack(side="left")
    entrada.bind("<Return>", revisar)
    entrada.focus_set()
    raiz.mainloop()
