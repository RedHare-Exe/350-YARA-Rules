rule pif
{
    meta:
    description = "Checks if a file is a .pif file."
    author = "Benjamin McKeever"
    date = "2025-10-27"

    strings:
    $var1 = { 00 78 49 4E 53 54 41 4c 4c }

    condition:
    $var1 at 0
}
