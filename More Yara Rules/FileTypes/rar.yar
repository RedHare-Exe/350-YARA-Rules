rule rar
{
    meta:
    description = "Checks if a file is a .rar file."
    author = "Benjamin McKeever"
    date = "2025-10-27"

    strings:
    $var1 = { 52 61 72 21 1A 07 00 }

    condition:
    $var1 at 0
}
