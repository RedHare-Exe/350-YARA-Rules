rule FileOutputStream {
    meta:
        description: = "Checks if a file contains FileOutputStream"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
    strings:
        $var1 = "new java.io.FileOutputStream("
    condition:
        $var1

}