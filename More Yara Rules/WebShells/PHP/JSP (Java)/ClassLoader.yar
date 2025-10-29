rule ClassLoader {
    meta:
        description: = "Checks if a file contains ClassLoader.defineClass"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
    strings:
        $var1 = "ClassLoader.defineClass("
    condition:
        $var1

}