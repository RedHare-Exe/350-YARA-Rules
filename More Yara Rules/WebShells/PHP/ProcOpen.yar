rule isProcOpen{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes proc_open function"
		date = "11/1/25"
	strings:
		$var1 = "proc_open"
	condition:
		$var1
}