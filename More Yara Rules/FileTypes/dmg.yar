rule dmg
{
    meta:
    description = "Checks if a file is a .dmg file."
    author = "Benjamin McKeever"
    date = "2025-10-27"

    strings:
    $var1 = { 42 5A 68 }
    $var2 = { 63 64 73 61 65 6E 63 72 }
    $var3 = { 65 6E 63 72 63 64 73 61 }
    $var4 = { 78 01 73 0D 62 62 60 }

    condition:
    $var1 at 0 or
    $var2 at 0 or
    $var3 at 0 or
    $var4 at 0
}
