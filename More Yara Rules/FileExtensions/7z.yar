rule SevenZ
{
    meta:
    description = "Checks if a file contains the .7z file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = "7z"

    condition:
    	$ext
}
