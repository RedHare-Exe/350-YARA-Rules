rule Runtime {
    meta:
        description = "Checks if a file contains Runtime exec"
        author = "Elizabeth Chadbourne"
        date = "2025-10-27"
        version = "1.0"
    strings:
        $var1 = "Runtime.getRuntime("
        $var2 = "exec("
    condition:
        $var1 and $var2

}