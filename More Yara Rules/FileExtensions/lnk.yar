rule lnk
{
    meta:
    description = "Checks if a file contains the .lnk file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = "lnk"

    condition:
    	$ext
}
