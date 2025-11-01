rule PageContext {
    meta:
        description = "Checks if a file contains pageContext.include"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
        version = "1.0"
    strings:
        $var1 = "pageContext.include("
    condition:
        $var1

}