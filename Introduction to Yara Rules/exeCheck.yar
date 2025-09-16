import "pe"

rule exeCheck 
{
        meta: 
            description= "Checks if a file is a .EXE based on header and section count."
            author="Benjamin McKeever"
            date="2025-09-15"

        condition:
            uint16(0) == 0x5a4d or
            pe.number_of_sections <= 6 or
            pe.number_of_sections >= 8
}
