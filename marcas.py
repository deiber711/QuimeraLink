"""Compatibilidad con los consumidores del anterior módulo de marcas."""
from analyzers.brand_analyzer import (
    CoincidenciaMarca,
    evaluar_marcas,
    lineas_catalogo,
    senales_marcas_en_pagina,
)

__all__ = ["CoincidenciaMarca", "evaluar_marcas", "lineas_catalogo", "senales_marcas_en_pagina"]
