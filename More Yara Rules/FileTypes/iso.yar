rule iso
{
    meta:
        description = "Checks if a file is an ISO disc image file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $var1 = {43 44 30 30 31}
        $var2 = {45 52 02 00 00}
        
    condition:
        $var1 at 0 or
        $var2 at 0
}
