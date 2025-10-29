rule CImport {
    meta:
        description = "Checks if a file contains c:import"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
    strings:
        $var1 = "c:import"
    condition:
        $var1

}