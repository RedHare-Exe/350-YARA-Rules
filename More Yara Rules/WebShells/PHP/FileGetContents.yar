rule isFileGetContents{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes file_get_contents function"
		date = "11/1/25"
	strings:
		$var1 = "file_get_contents("
	condition:
		$var1
}