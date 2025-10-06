rule adx
{
    meta:
    description = "Checks if a file is a .adx file."
    author = "Benjamin McKeever"
    date = "2025-10-06"

    strings:
    $var1 = { 80 00 }

    condition:
    $var1 at 0
}
