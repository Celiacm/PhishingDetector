def score_a_estado(score, motivos):
    phishing_keywords = [
        "Enlace sospechoso",
        "Enlace con dirección IP",
        "Lenguaje de urgencia",
        "Dominio gratuito",
        "Return-Path difiere",
        "Adjunto con extensión inusual"
    ]

    # 🚨 1. Score altísimo o 2 palabras muy graves -> Phishing
    if score >= 11 or sum(any(k in m for k in phishing_keywords) for m in motivos) >= 2:
        return "Phishing"

    # ⚠️ 2. Score medio-alto o 1 palabra grave -> Sospechoso
    if 7 <= score < 11 or sum(any(k in m for k in phishing_keywords) for m in motivos) == 1:
        return "Sospechoso"

    # ✅ 3. Score bajo y sin palabras graves -> Seguro
    return "Seguro"
