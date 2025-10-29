rule PowershellDetect {
    meta:
        description: = "Checks if a executes Powershell"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
    strings:
        $var1 = "powershell.exe "
        $var2 = "powershell"
    condition:
        $var1 or $var2

}