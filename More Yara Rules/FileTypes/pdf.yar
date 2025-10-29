rule plist
{
    meta:
    description = "Checks if a file is a .pdf file."
    author = "Benjamin McKeever"
    date = "2025-10-27"

    strings:
    $var1 = { 25 50 44 46 }

    condition:
    $var1 at 0
}
