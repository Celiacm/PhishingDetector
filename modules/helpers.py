# modules/helpers.py
# helpers.py

def score_a_estado(score, motivos):
    phishing_keywords = [
        "Enlace sospechoso",
        "Enlace con dirección IP",
        "Lenguaje de urgencia",
        "Dominio gratuito",
        "Return-Path difiere",
        "Adjunto con extensión inusual"
    ]

    if score >= 12 and any(any(k in m for k in phishing_keywords) for m in motivos):
        return "Phishing"
    elif score >= 8 and len(motivos) >= 3:
        return "Sospechoso"
    else:
        return "Seguro"
