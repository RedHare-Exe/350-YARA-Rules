rule isFWrite{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes fwrite function"
		date = "11/1/25"
	strings:
		$var1 = "fwrite("
	condition:
		$var1
}