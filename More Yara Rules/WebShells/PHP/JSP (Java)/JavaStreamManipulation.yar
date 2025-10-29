rule JavaStreamManipulation {
    meta:
        description = "Checks if a file contains java stream manipulation"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
    strings:
        $var1 = "System.setIn("
        $var2 = "System.setOut("
        $var3 = "System.setErr("
    condition:
        $var1 or $var2 or $var3

}