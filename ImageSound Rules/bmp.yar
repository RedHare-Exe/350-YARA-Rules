rule bmp {
	meta:
		description = "Checks if a file is a .bmp file"
		author = "Elizabeth Chadbourne"
		date = "2025-10-06"
		
	strings:
		$gif = { 42 4D }
		
	condition:
		$gif at 0
}