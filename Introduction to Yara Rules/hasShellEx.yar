import "pe"

rule hasShellEx{
    meta:
        author="Benjamin McKeever"
		description="Tests if a file uses any of the ShellExecute commands."
		date="2025-09-16" 

    condition:
        pe.imports("Shell32.dll", "ShellExecute") or
        pe.imports("Shell32.dll", "ShellExecuteEx") or
        pe.imports("Shell32.dll", "ShellExecuteExA") or
        pe.imports("Shell32.dll", "ShellExecuteExW")
}