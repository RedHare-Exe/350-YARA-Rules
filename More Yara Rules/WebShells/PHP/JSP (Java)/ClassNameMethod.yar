rule ClassNameMethod {
    meta:
        description = "Checks if a file contains ClassforNamegetMethod"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
    strings:
        $var1 = "Class.forName(.getMethod(.invoke("
    condition:
        $var1

}