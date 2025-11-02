rule isMoveUploadedFile{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes move_uploaded_file function"
		date = "11/1/25"
	strings:
		$var1 = "move_uploaded_file("
	condition:
		$var1
}