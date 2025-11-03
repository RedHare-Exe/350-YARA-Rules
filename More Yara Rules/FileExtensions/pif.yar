rule pif
{
    meta:
    description = "Checks if a file contains the .pif file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = ".pif"

    condition:
    	$ext
}
