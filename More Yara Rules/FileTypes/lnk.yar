rule lnk
{
    meta:
    description = "Checks if a file is an .lnk file."
    author = "Avery Luther"
    date = "2025-10-31"

    strings:
	$sig = {4c 00 00 00 01 14 02 00}
    condition:
    	$sig at 0
}
