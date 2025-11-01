rule JavaNetSocket {
    meta:
        description = "Checks if a file contains java.net.Socket"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
        version = "1.0"
    strings:
        $var1 = "java.net.Socket"
    condition:
        $var1

}