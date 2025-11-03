rule swf
{
    meta:
        description = "Checks if a file is a Flash SWF file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $swf1 = {46 57 53}
        $swf2 = {43 57 53}
        $swf3 = {5A 57 53}
        
    condition:
        $swf1 at 0 or
        $swf2 at 0 or
        $swf3 at 0
}
