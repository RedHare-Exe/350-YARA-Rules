rule GetRequestDispatcher {
    meta:
        description = "Checks if a file contains getRequestDispatcher"
        author = "Elizabeth Chadbourne"
        date = "2025-10-28"
    strings:
        $var1 = "request.getRequestDispatcher(.include("
    condition:
        $var1

}