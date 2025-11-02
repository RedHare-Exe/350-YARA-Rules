rule isPOpen{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes popen function"
		date = "11/1/25"
	strings:
		$var1 = "popen("
	condition:
		$var1
}