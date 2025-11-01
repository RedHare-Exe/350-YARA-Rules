rule ClassNameMethod {
    meta:
        description = "Checks if a file contains ClassforNamegetMethod"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
        version = "1.0"
    strings:
        $var1 = "Class.forName("
        $var2 = ".getMethod("
        $var3 = ".invoke("
    condition:
        all of them

}