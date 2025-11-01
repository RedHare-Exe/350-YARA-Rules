rule ProcessBuilder {
    meta:
        description = "Checks if a file contains ProcessBuilder"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
        version = "1.0"
    strings:
        $runtime = "ProcessBuilder.start("
    condition:
        $runtime

}