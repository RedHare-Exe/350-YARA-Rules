rule IMG
{
    meta:
    description = "Checks if a file is a .IMG file."
    author = "mila delmas"
    date = "2025-10-06"

    strings:
    $var1 = {53 43 4D 49}

    condition:
    $var1 at 0
}
