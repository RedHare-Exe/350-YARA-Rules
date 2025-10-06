rule wav
{
    meta:
    description = "Checks if a file is a .WAV file."
    author = "Benjamin McKeever"
    date = "2025-10-06"

    strings:
    $var1 = { 52 49 46 46 ?? ?? ?? ?? }
    $var2 = { 57 41 56 45 66 6D 74 20 }

    condition:
    $var1 at 0 or
    $var2 at 0
}
