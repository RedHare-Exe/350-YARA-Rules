rule JspInclude {
    meta:
        description = "Checks if a file contains jsp:include"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
        version = "1.0"
    strings:
        $var1 = "jsp:include"
    condition:
        $var1

}