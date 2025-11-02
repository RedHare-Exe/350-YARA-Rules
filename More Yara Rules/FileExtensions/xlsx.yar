rule xlsx
{
    meta:
    description = "Checks if a file contains the .xlsx file extension"
    author = "Avery Luther"
    date = "2025-11-2"

    strings:
	$ext = "xlsx"

    condition:
    	$ext
}
