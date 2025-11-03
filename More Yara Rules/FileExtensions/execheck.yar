rule exe
{
    meta:
    description = "Checks if a file contains the .exe file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = ".exe"

    condition:
    	$ext
}
