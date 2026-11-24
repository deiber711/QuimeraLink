"""Campos sensibles y destinos declarados en el HTML estático."""
from collections import defaultdict
from dataclasses import dataclass
import re
import unicodedata



@dataclass(frozen=True)
class Formulario:
    origen: str | None
    tiene_password: bool
    datos_financieros: bool = False
    destinos_botones: tuple[str | None, ...] = ()


_PASSWORD = re.compile(r'\b(password|passwd|contrasena|clave de acceso)\b')
_FINANZAS = re.compile(
    r'\b(cvv2?|cvc2?|iban|clabe|card ?number|cc ?(number|csc|exp)|'
    r'(credit|debit) card|routing number|bank account|account number|'
    r'(numero|titular) (de (la )?)?tarjeta|tarjeta de (credito|debito)|'
    r'(numero de cuenta|cuenta bancaria))\b'
)
_TOKENS_TARJETA = set('cc-name cc-given-name cc-additional-name cc-family-name cc-number '
                      'cc-exp cc-exp-month cc-exp-year cc-csc cc-type'.split())


def _tipos(texto):
    texto = re.sub(r'([a-z])([A-Z])', r'\1 \2', texto)
    texto = ''.join(c for c in unicodedata.normalize('NFKD', texto.casefold())
                    if not unicodedata.combining(c)).replace('_', ' ')
    texto = ' '.join(re.findall(r'\w+', texto))
    return bool(_PASSWORD.search(texto)), bool(_FINANZAS.search(texto))


class FormulariosHTML:
    def __init__(self):
        self.forms = []
        self.ids = {}
        self.actual = None
        self.campos = []
        self.botones = []
        self.etiquetas = {}
        self.etiqueta = None
        self.texto = ''
        self.primero = set()
        self.numero_etiqueta = 0

    def inicio(self, tag, attrs):
        identificador = attrs.get('id')
        primero = bool(identificador and identificador not in self.primero)
        if primero:
            self.primero.add(identificador)
        if tag == 'form' and self.actual is None:
            self.actual = len(self.forms)
            self.forms.append((attrs.get('action'), attrs.get('method')))
            if primero:
                self.ids[identificador] = self.actual
        if tag == 'label':
            self.numero_etiqueta += 1
            self.etiqueta = ('id', attrs['for']) if 'for' in attrs else ('label', self.numero_etiqueta)
            self.texto = ''
        if tag not in {'input', 'select', 'textarea', 'button'} or 'disabled' in attrs:
            return
        propietario = (attrs['form'] or '') if 'form' in attrs else self.actual
        tipo = (attrs.get('type') or '').lower()
        envio = (tag == 'button' and tipo not in {'button', 'reset'}) or (tag == 'input' and tipo in {'submit', 'image'})
        if envio and ('formaction' in attrs or 'formmethod' in attrs):
            accion = (attrs['formaction'] or '') if 'formaction' in attrs else None
            metodo = (attrs['formmethod'] or '') if 'formmethod' in attrs else None
            self.botones.append((propietario, accion, metodo))
        if tag == 'button' or (tag == 'input' and tipo not in {'', 'text', 'tel', 'number', 'password', 'search', 'email'}):
            return
        if 'readonly' in attrs or 'hidden' in attrs:
            return
        descripcion = ' '.join(attrs.get(k) or '' for k in ('id', 'name', 'placeholder', 'aria-label'))
        password, financiero = _tipos(descripcion)
        tokens = set((attrs.get('autocomplete') or '').lower().split())
        password |= tipo == 'password' or bool(tokens & {'current-password', 'new-password'})
        financiero |= bool(tokens & _TOKENS_TARJETA)
        self.campos.append((propietario, identificador if primero else None, self.etiqueta, password, financiero))

    def datos(self, texto):
        if self.etiqueta is not None and len(self.texto) < 512:
            self.texto += texto[:512 - len(self.texto)]

    def fin(self, tag):
        if tag == 'form':
            self.actual = None
        if tag == 'label' and self.etiqueta is not None:
            previo = self.etiquetas.get(self.etiqueta, (False, False))
            p, f = _tipos(self.texto)
            self.etiquetas[self.etiqueta] = (previo[0] or p, previo[1] or f)
            self.etiqueta = None

    def resultados(self, url, base, referencia, origen):
        def propietario(ref):
            return self.ids.get(ref) if isinstance(ref, str) else ref

        def destino(accion, metodo):
            if (metodo or '').lower() == 'dialog':
                return None
            accion = (accion or '').strip()
            if not accion:
                return origen(url)
            return origen(referencia(base, accion))

        categorias = defaultdict(set)
        for ref, ident, etiqueta, p, f in self.campos:
            claves = [('id', ident)] if ident else []
            if etiqueta and etiqueta[0] == 'label':
                claves.append(etiqueta)
            for clave in claves:
                lp, lf = self.etiquetas.get(clave, (False, False))
                p, f = p or lp, f or lf
            tipos = categorias[propietario(ref)]
            if p:
                tipos.add('password')
            if f:
                tipos.add('finanzas')
        alternativas = defaultdict(dict)
        for ref, accion, metodo in self.botones:
            indice = propietario(ref)
            if indice is not None:
                a, m = self.forms[indice]
                receptor = destino(a if accion is None else accion, m if metodo is None else metodo)
                alternativas[indice][receptor] = None
        resultado = []
        for indice, (accion, metodo) in enumerate(self.forms):
            principal = destino(accion, metodo)
            opciones = alternativas[indice]
            opciones.pop(principal, None)
            tipos = categorias[indice]
            resultado.append(Formulario(principal, 'password' in tipos, 'finanzas' in tipos, tuple(opciones)))
        return tuple(resultado)
