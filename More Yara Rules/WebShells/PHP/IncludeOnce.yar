rule isIncludeOnce{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes include_once function"
		date = "11/1/25"
	strings:
		$var1 = "include_once("
	condition:
		$var1
}