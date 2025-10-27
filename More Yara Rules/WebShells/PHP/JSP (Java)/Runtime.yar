rule Runtime {
    meta:
        description: = "Checks if a file contains Runtime exec"
        author = "Elizabeth Chadbourne"
        date = "2025-10-27"
    strings:
        $runtime = "Runtime.getRuntime(exec("
    condition:
        $runtime

}