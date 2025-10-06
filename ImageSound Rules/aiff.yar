rule aiff
{
    meta:
    description = "Checks if a file is a .aiff file."
    author = "Benjamin McKeever"
    date = "2025-10-06"

    strings:
    $var1 = { 46 4F 52 4D 00 }

    condition:
    $var1 at 0
}
