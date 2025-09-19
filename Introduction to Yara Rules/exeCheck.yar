import "pe"

rule exeCheck 
{
        meta: 
            description= "Checks if a file is a .EXE"
            author="Avery Luther, Benjamin McKeever"
            date="2025-09-18"

        condition:
            pe.is_pe and
            (pe.characteristics & pe.EXECUTABLE_IMAGE) and
            not (
                (pe.characteristics & pe.DLL) or 
                (pe.subsystem ==  pe.SUBSYSTEM_WINDOWS_BOOT_APPLICATION) or
                (pe.characteristics & pe.SYSTEM) or
                for any section in pe.sections : (
                    section.name == "PAGE" or
                    section.name == "NONPAGE" or
                    section.name == "INIT" or
                    section.name == "GFIDS"
                    )
            )
}