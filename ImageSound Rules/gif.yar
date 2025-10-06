rule gif {
	meta:
		description = "Checks if a file is a .GIF file"
		author = "Elizabeth Chadbourne"
		date = "2025-10-06"
		
	strings:
		$gif = { 47 49 46 38 }
		
	condition:
		$gif at 0
}