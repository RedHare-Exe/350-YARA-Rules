rule REPLACE
{
    meta:
    description = "Checks if a file contains the .REPLACE file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = ".REPLACE"

    condition:
    	$ext
}
