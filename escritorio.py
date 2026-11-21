from base64 import b64encode
from queue import Empty, Queue
from threading import Thread
import tkinter as tk
from tkinter import ttk

from analisis import analizar
from captura import imagen


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
        return etiqueta

    texto("Revisar un enlace", 22, "#164d49", True)
    texto("Pega la dirección para revisarla en tu equipo sin visitar la página.")
    entrada = ttk.Entry(marco, font=("Segoe UI", 12))
    entrada.pack(fill="x", ipady=5)
    acciones = ttk.Frame(marco)
    acciones.pack(anchor="w", pady=14)
    dominio = texto("", 12, negrita=True)
    aviso = texto("")
    detalle = texto("")
    estado = texto("", 10)
    destino = None
    ocupado = False
    cola = Queue()

    def limpiar(*_):
        nonlocal destino
        destino = None
        captura.state(["disabled"])
        for etiqueta in (dominio, aviso, detalle, estado):
            etiqueta.configure(text="")

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
        if resultado.senales:
            aviso.configure(text="Revisa estas señales antes de continuar", fg="#854805")
            detalle.configure(text="\n".join("• " + s for s in resultado.senales) +
                              "\n\nEvita ingresar datos personales. Verifica el enlace por un canal oficial.")
        else:
            aviso.configure(text="Sin señales evidentes en la dirección", fg="#334b52")
            detalle.configure(text="La autenticidad sigue sin confirmarse. Verifica el sitio antes de ingresar datos.")
        destino = resultado.url_captura
        if destino:
            captura.state(["!disabled"])
            estado.configure(text="La captura opcional visita el sitio desde tu conexión y muestra una imagen.")
        else:
            estado.configure(text="Vista previa no disponible para esta dirección.")

    def recibir():
        nonlocal ocupado
        try:
            datos = cola.get_nowait()
        except Empty:
            raiz.after(100, recibir)
            return
        ocupado = False
        entrada.state(["!disabled"])
        boton.state(["!disabled"])
        captura.state(["!disabled"])
        if datos is None:
            estado.configure(text="No se pudo obtener la captura. El análisis del enlace sigue disponible.")
            return
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

    def solicitar():
        nonlocal ocupado
        if not destino or ocupado:
            return
        url = destino
        ocupado = True
        for control in (entrada, captura, boton):
            control.state(["disabled"])
        estado.configure(text="Obteniendo la imagen…")

        def trabajo():
            try:
                cola.put(imagen(url))
            except Exception:
                cola.put(None)

        Thread(target=trabajo).start()
        raiz.after(100, recibir)

    valor = tk.StringVar()
    entrada.configure(textvariable=valor)
    valor.trace_add("write", limpiar)
    boton = ttk.Button(acciones, text="Analizar enlace", command=revisar)
    boton.pack(side="left")
    captura = ttk.Button(acciones, text="Ver captura", command=solicitar)
    captura.pack(side="left", padx=10)
    captura.state(["disabled"])
    entrada.bind("<Return>", revisar)
    entrada.focus_set()
    raiz.mainloop()
