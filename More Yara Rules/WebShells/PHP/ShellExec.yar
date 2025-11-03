rule isShellExec{
	meta:
		author = "Ellis Tomsen"
		description = "PHP includes shell_exec function"
		date = "11/1/25"
	strings:
		$var1 = "shell_exec("
	condition:
		$var1
}