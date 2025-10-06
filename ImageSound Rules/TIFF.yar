rule tiff
{
    meta:
    description = "Checks if a file is a .TIFF file."
    author = "Benjamin Ware"
    date = "2025-10-06"

    strings:
    $header1 = { 46 20 49 }
    $header2 = { 49 49 2A 00 }
    $header2 = { 4D 4D 00 2A }
    $header2 = { 4D 4D 00 2B }

    condition:
    $header1 at 0 or
    $header2 at 0 or
    $header3 at 0 or
    $header4 at 0 
}
