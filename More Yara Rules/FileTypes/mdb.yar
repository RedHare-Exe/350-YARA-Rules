rule mdb
{
    meta:
        description = "Checks if a file is an Access MDB file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $var1 = {00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42}
        
    condition:
        $var1 at 0
}
