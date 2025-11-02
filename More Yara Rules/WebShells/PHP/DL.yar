rule isDL{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes dl function"
		date = "11/1/25"
	strings:
		$var1 = "dl("
	condition:
		$var1
}