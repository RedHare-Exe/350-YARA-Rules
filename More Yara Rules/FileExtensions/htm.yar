rule htm
{
    meta:
    description = "Checks if a file contains the .htm file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = "htm"

    condition:
    	$ext
}
