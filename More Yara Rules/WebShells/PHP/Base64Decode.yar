rule isBase64{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes base64_decode function"
		date = "11/1/25"
	strings:
		$var1 = "base64_decode("
	condition:
		$var1
}