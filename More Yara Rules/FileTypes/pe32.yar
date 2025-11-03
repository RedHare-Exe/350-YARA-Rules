rule pe32
{
    meta:
        description = "Checks if a file is a 32-bit Windows PE executable"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $mz = {4D 5A}
        $pe = {50 45 00 00}
        $bit32 = {4C 01}
        
    condition:
        $mz at 0 and $pe and $bit32
}
