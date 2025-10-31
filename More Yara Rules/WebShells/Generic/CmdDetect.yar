rule CmdDetect {
    meta:
        description = "Checks if a file executes cmd"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
    strings:
        $var1 = "cmd.exe /c"
        $var2 = "cmd /c"
    condition:
        $var1 or $var2

}