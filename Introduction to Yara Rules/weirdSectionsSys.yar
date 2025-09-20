import "pe"

rule weirdSysFile 
{
        meta: 
            description= "Checks if a .sys file has more than 13 or less than 9 secitons"
            author="Avery Luther"
            date="2025-09-18"

        condition:
			pe.is_pe and
			(pe.characteristics & pe.SYSTEM) and 
			( pe.number_of_sections >= 13) and 
			(pe.number_of_sections <= 9)
}