import "pe"

rule weirdExeFile 
{
        meta: 
            description= "Checks if a .exe file has more than 8 or less than 6 secitons"
            author="Avery Luther"
            date="2025-09-18"

        condition:
            pe.is_pe and
            pe.characteristics & pe.EXECUTABLE_IMAGE and
            not (
                (pe.characteristics & pe.DLL) or 
                (pe.subsystem ==  pe.SUBSYSTEM_WINDOWS_BOOT_APPLICATION) or
                (pe.characteristics & pe.SYSTEM) or
                for any section in pe.sections : ( section.name == "PAGE" or section.name == "NONPAGE" or section.name == "INIT" or section.name == "GFIDS" )

            ) and 
            (pe.number_of_sections > 8 or 
            pe.number_of_sections < 6)
}
