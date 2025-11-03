rule dll
{
    meta:
    description = "Checks if a file contains the .dll file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = ".dll"

    condition:
    	$ext
}
