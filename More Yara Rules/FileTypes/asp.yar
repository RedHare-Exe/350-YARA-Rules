rule asp
{
    meta:
        description = "Checks if a file is an ASP file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $asp1 = "<%@"
        $asp2 = "Response.Write"
        $asp3 = "Server.CreateObject"
        
    condition:
        any of them
}
