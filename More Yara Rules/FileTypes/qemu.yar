rule qemu
{
    meta:
    description = "Checks if a file is a .qemu file."
    author = "Benjamin McKeever"
    date = "2025-10-27"

    strings:
    $var1 = { 51 46 49 }

    condition:
    $var1 at 0
}
