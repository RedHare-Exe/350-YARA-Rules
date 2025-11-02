rule isGzInflate{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes gzinflate function"
		date = "11/1/25"
	strings:
		$var1 = "gzinflate("
	condition:
		$var1
}