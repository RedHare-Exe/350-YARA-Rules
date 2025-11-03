rule rar
{
    meta:
    description = "Checks if a file contains the .rar file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = ".rar"

    condition:
    	$ext
}
