rule JavaMethod {
    meta:
        description = "Checks if a file contains java.lang.reflect.Method"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
        version = "1.0"
    strings:
        $var1 = "java.lang.reflect.Method.invoke("
    condition:
        $var1

}