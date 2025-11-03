rule doc
{
    meta:
        description = "Checks if a file is a Word DOC file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $var1 = {0D 44 4F 43}
        $var2 = {CF 11 E0 A1 B1 1A E1 00}
        $var3 = {DB A5 2D 00}
        $var4 = {EC A5 C1 00}
        
    condition:
        $var1 at 0 or
        $var2 at 0 or
        $var3 at 0 or
        $var4 at 512
}
