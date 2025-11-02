rule isFOpen{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes fopen function"
		date = "11/1/25"
	strings:
		$var1 = "fopen("
	condition:
		$var1
}