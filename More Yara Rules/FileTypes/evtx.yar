rule evtx
{
    meta:
        description = "Checks if a file is a Windows Event Log EVTX file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $var1 = {45 6C 66 46 69 6C 65 00}
        
    condition:
        $var1 at 0
}
