import "pe"

rule scr
{
    meta:
        description = "Checks if a file is a Windows screensaver SCR file"
        author = "mila delmas"
        date = "2025-11-02"
        
    strings:
        $mz = {4D 5A}
        $string = "Screen Saver" wide
        
    condition:
        $mz at 0 and
        $string and
        pe.number_of_sections == 7
}
