rule xls
{
    meta:
        description = "Checks if a file is an Excel XLS file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $var1 = {09 08 10 00 00 06 05 00}
        $var2 = {FD FF FF FF 10}
        $var3 = {FD FF FF FF 1F}
        $var4 = {FD FF FF FF 22}
        $var5 = {FD FF FF FF 23}
        $var6 = {FD FF FF FF 28}
        $var7 = {FD FF FF FF 29}
        
    condition:
        $var1 at 512 or
        $var2 at 512 or
        $var3 at 512 or
        $var4 at 512 or
        $var5 at 512 or
        $var6 at 512 or
        $var7 at 512
}
