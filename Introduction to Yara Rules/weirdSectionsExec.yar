import "pe"

rule weirdSectionsExec{
    meta:
        author="Benjamin McKeever"
		description="Tests if a file has exectuable sections other than .text or .rdata"
		date="2025-09-16" 

    condition:
        for any section in pe.sections : ( 
            (section.characteristics & pe.SECTION_MEM_EXECUTE) and
            section.name != ".text" and
            section.name != "fothk"
            )
}