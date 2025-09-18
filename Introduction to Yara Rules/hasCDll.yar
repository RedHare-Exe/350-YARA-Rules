import "pe"

rule hasCDll{
    meta:
        author="Benjamin McKeever"
		description="Tests if a file imports the DLL 'mscvrt.dll'. Could feasible be used to check for any dll."
		date="2025-09-16" 

    condition:
        pe.imports("MSVCRT.DLL")
}