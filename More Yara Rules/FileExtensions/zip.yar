rule zip
{
    meta:
    description = "Checks if a file contains the .zip file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = "zip"

    condition:
    	$ext
}
