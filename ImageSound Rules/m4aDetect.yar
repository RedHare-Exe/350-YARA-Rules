rule m4aDetected 
{
        meta: 
            description= "Checks if a file is a m4a file"
            author="Avery Luther"
            date="2025-10-6"
		strings:
			$flacID = {66 74 79 70 4D 34 41 20}
        condition:
			$flac at 4
}