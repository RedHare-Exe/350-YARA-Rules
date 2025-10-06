rule ra
{
    meta:
    description = "Checks if a file is a .ra file."
    author = "Benjamin McKeever"
    date = "2025-10-06"

    strings:
    $var1 = { 2E 52 4D 46 00 00 00 12 }
    $var2 = { 2E 72 61 FD 00 }

    condition:
    $var1 at 0 or $var2 at 0
}
