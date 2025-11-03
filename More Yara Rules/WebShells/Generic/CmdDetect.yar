rule CmdDetect {
    meta:
        description = "Checks if a file executes cmd"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
        version = "1.0"
    strings:
        $var1 = "cmd.exe /c" nocase
        $var2 = "cmd /c" nocase
    condition:
        $var1 or $var2

}