"""
Liste V1 des fonctionnalités sensibles pour l'évaluation de Permissions-Policy
— mission section 9. Centralisée : checks/headers.py ne doit contenir aucun
nom de fonctionnalité en dur.

Le critère du contrôle (SPEC.md §8.5 / mission §9) est : la politique
restreint-elle explicitement AU MOINS UNE de ces fonctionnalités ? Ce n'est
pas une évaluation de la "perfection" de la politique.
"""

SENSITIVE_PERMISSIONS_FEATURES: tuple[str, ...] = (
    "camera",
    "microphone",
    "geolocation",
    "payment",
    "usb",
    "bluetooth",
    "serial",
    "hid",
    "fullscreen",
)
