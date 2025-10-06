rule m4aDetected 
{
        meta: 
            description= "Checks if a file is a m4a file"
            author="Avery Luther"
            date="2025-10-6"
		strings:
			$flacID = {30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C}
        condition:
			$flac at 0
}