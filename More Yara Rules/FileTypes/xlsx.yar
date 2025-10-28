rule xlsx
{
    meta:
    description = "Checks if a file is a .xlsx file."
    author = "Benjamin McKeever"
    date = "2025-10-27"

    strings:
    $var1 = { 50 4B 03 04 }
    $var2 = "xl/"

    condition:
    $var1 at 0 and
    $var2 at 0x1E
}
