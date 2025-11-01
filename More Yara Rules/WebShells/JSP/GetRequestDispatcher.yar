rule GetRequestDispatcher {
    meta:
        description = "Checks if a file contains getRequestDispatcher"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
        version = "1.0"
    strings:
        $var1 = "request.getRequestDispatcher("
        $var2 = ".include("
    condition:
        all of them

}