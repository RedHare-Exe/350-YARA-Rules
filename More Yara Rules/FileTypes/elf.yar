rule elf
{
    meta:
    description = "Checks if a file is an .elf file."
    author = "Avery Luther"
    date = "2025-10-27"

    strings:
	$sig = {7f 45 4C 46}
    condition:
    	$sig at 0
}
