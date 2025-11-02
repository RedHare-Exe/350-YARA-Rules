rule isCopy{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes copy function"
		date = "11/1/25"
	strings:
		$var1 = "copy("
	condition:
		$var1
}