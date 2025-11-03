rule gz
{
    meta:
        description = "Checks if a file is a GZIP compressed file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $var1 = {1F 8B 08}
        
    condition:
        $var1 at 0
}
