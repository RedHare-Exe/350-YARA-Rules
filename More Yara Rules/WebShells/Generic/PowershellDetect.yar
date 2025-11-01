rule PowershellDetect {
    meta:
        description = "Checks if a file executes Powershell"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
        version = "1.0"
    strings:
        $var1 = "powershell.exe " nocase
        $var2 = "powershell" nocase
    condition:
        $var1 or $var2

}