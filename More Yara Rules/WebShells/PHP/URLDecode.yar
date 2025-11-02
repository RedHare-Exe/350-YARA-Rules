rule isURLDecode{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes urldecode function"
		date = "11/1/25"
	strings:
		$var1 = "urldecode("
	condition:
		$var1
}