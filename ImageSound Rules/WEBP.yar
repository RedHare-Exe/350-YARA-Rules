rule tiff
{
    meta:
    description = "Checks if a file is a .WEBP file."
    author = "Benjamin Ware"
    date = "2025-10-06"

    strings:
    $header1 = { 57 45 42 50 }

    condition:
    $header1 at 8 or
    $header1 at 0
}
