rule JavaStreamManipulation {
    meta:
        description = "Checks if a file contains java stream manipulation"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
        version = "1.0"
    strings:
        $var1 = "System.setIn("
        $var2 = "System.setOut("
        $var3 = "System.setErr("
    condition:
        any of them

}