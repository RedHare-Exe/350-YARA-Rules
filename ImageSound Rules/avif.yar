rule avif {
	meta:
		description = "Checks if a file is a avif file"
		author = "Elizabeth Chadbourne"
		date = "2025-10-06"
		
	strings:
		$gif = { 66 74 79 70 61 76 69 66 }
		
	condition:
		$gif at 4
}