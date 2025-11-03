rule vhd
{
    meta:
    description = "Checks if a file is an .vhd file with dynamic allocation."
    author = "Avery Luther"
    date = "2025-11-1"

    strings:
	$sig = "conectix"
    condition:
    	$sig at 0
}
