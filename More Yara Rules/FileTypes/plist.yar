rule plist
{
    meta:
    description = "Checks if a file is a .plist file."
    author = "Benjamin McKeever"
    date = "2025-10-27"

    strings:
    $var1 = { 62 70 6C 69 73 74 }

    condition:
    $var1 at 0
}
