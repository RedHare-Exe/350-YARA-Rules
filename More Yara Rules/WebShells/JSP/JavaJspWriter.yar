rule JavaJspWriter {
    meta:
        description = "Checks if a file contains JavaJspWriter"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
        version = "1.0"
    strings:
        $var1 = "java.servlet.jsp.JespWriter.print("
    condition:
        $var1

}