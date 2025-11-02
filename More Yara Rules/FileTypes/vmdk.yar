rule vmdk
{
    meta:
    description = "Checks if a file is an .vmdk file."
    author = "Avery Luther"
    date = "2025-11-1"

    strings:
	$sig = "# Disk Descriptor"
    condition:
    	$sig at 0
}
