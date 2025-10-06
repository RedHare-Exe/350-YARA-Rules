rule png
{
    meta:
    description = "Checks if a file is a .PNG file."
    author = "Benjamin Ware"
    date = "2025-10-06"

    strings:
    $header1 = { 89 50 4E 47 0D 0A 1A 0A }

    condition:
    $header1 at 0 
}
