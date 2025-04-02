rule SuspiciousExecutable {
    meta:
        description = "Archivo ejecutable o script sospechoso detectado"
    strings:
        $mz = {4D 5A}
        $a = "This program cannot be run in DOS mode"
        $b = /powershell.*-encodedcommand/i
    condition:
        $mz at 0 or any of ($a, $b)
}

rule posible_phishing
{
    strings:
        $phish1 = "verify your account"
        $phish2 = "reset your password"
        $phish3 = "click here"
    condition:
        (any of them) and filesize < 100KB

}


rule Phishing_HTML_Form {
    meta:
        description = "Formulario HTML sospechoso para captura de credenciales"
    strings:
        $form_action = /<form[^>]*action=["']?http[^>]*>/ nocase
        $login_keywords = /password|login|username|verify/i
    condition:
        $form_action and #login_keywords > 0
}

rule Suspicious_HTML_Script {
    meta:
        description = "Script potencialmente malicioso incrustado en HTML"
    strings:
        $script_tag = "<script" nocase
        $on_event = /on\w+ *= *"javascript:/ nocase
    condition:
        $script_tag and $on_event
}

rule Office_Macro_Suspicious {
    meta:
        description = "Documento Office con macros potencialmente maliciosas"
    strings:
        $macro1 = "AutoOpen" nocase
        $macro2 = "ThisDocument" nocase
        $macro3 = "VBA=" nocase
        $macro4 = "AutoExec" nocase
        $macro5 = "Workbook_Open" nocase
        $macro6 = "Shell.Application" nocase
    condition:
        any of them
}

rule HTML_AutoRedirect {
    meta:
        description = "Redirección automática sospechosa en HTML"
    strings:
        $metaRefresh = /<meta\s+http-equiv\s*=\s*["']?refresh["']?/ nocase
        $windowLoc = "window.location" nocase
        $documentLoc = "document.location" nocase
    condition:
        any of them
}

rule Suspicious_JS_Obfuscation {
    meta:
        description = "Código JavaScript ofuscado en HTML"
    strings:
        $eval = "eval(" nocase
        $fromChar = "fromcharcode" nocase
        $atob = "atob(" nocase
        $unesc = "unescape(" nocase
    condition:
        any of them
}
