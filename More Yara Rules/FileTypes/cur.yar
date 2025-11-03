rule cur
{
    meta:
        description = "Checks if a file is a Windows cursor CUR file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $cur = {00 00 02 00}
        
    condition:
        $cur at 0
}
