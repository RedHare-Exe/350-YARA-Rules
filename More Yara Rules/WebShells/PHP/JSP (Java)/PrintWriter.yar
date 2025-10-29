rule PrintWriter {
    meta:
        description: = "Checks if a file contains PrintWriter"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
    strings:
        $var1 = "new java.io.PrintWriter("
    condition:
        $var1

}