rule eps
{
    meta:
        description = "Checks if a file is an EPS file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $var1 = {25 21 50 53 2D 41 64 6F}
        $var2 = {C5 D0 D3 C6}
        
    condition:
        $var1 at 0 or
        $var2 at 0
}
