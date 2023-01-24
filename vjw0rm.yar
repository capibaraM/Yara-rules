rule suspicious_base64_vjw0rm {
    meta:
    description = "Detects common functions used by vjw0rm or vjw0rm string"
    author = "Andres Nahuel Antola"
    date = "13/11/2022"
    hash = "3a7d372c4d53bb1ab91c7dd57e0234946a4fe303a5d17f3883006c0fa96a9959"

    strings:
        $string1 = "WScript" base64
        $string2  = "HKCU" base64
        $string3 = "AntiVirusProduct" base64
        $string4 = "POST" base64
        $string5 = "RegWrite" base64
        $string6 = "split" base64
        $string7 = "CreateTextFile" base64
        $string8 = "eval" base64
        $string9 = "run" base64
        $vjw0rm = "vjw0rm" base64

    condition:
        all of ($string*) or $vjw0rm
}