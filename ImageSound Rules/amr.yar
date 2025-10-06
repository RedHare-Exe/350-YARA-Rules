rule amr
{
    meta:
    description = "Checks if a file is a .AMR file."
    author = "Benjamin McKeever"
    date = "2025-10-06"

    strings:
    $var1 = { 23 21 41 4D 52 }

    condition:
    $var1 at 0
}
