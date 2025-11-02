rule rtf
{
    meta:
    description = "Checks if a file contains the .rtf file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = "rtf"

    condition:
    	$ext
}
