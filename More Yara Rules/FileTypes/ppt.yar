rule ppt
{
    meta:
        description = "Checks if a file is a PowerPoint PPT file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $var1 = {00 6E 1E F0}
        $var2 = {0F 00 E8 03}
        $var3 = {A0 46 1D F0}
        $var4 = {FD FF FF FF 0E 00 00 00}
        $var5 = {FD FF FF FF 1C 00 00 00}
        $var6 = {FD FF FF FF 43 00 00 00}
        
    condition:
        $var1 at 512 or
        $var2 at 512 or
        $var3 at 512 or
        $var4 at 512 or
        $var5 at 512 or
        $var6 at 512
}
