rule isInclude{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes include function"
		date = "11/1/25"
	strings:
		$var1 = "include("
	condition:
		$var1
}