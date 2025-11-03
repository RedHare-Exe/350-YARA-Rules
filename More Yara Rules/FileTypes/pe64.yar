rule pe64
{
    meta:
        description = "Checks if a file is a 64-bit Windows PE executable"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $mz = {4D 5A}
        $pe = {50 45 00 00}
        $bit64 = {64 86}
        
    condition:
        $mz at 0 and $pe and $bit64
}
