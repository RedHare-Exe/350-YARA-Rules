rule matchesDasuwerugwuerwq {
    meta:
        description="Finds files that are similar to dasuwerugwuerwq.exe file when packed."
            author="Benjamin McKeever"
            date="2025-10-04"
            threatFamily="Thug Lyfe"

    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX2"

    condition:
        all of them
}


rule matchesUNPACKDasuwerugwuerwq
{
        meta: 
            description= "Finds files that are similar to the dasuwerugwuerwq.exe file when unpacked."
            author="Benjamin McKeever"
            date="2025-10-03"
            threatFamily="Thug Lyfe"

        strings:
            $thugLyfe = "thug.lyfe"

        condition:
            $thugLyfe
}

rule matchesSetup {
        meta:
            description="Finds files that are similar to setup.exe."
            author="Benjamin McKeever"
            date="2025-10-04"
            threatFamily="Thug Lyfe"
        
        strings:
            $dosHeader = "!This program cannot be run in DOS mode."
        
        condition:
            #dosHeader == 2
}

rule matchesSimplecalc {
        meta:
                description= "Identifies a file that uses the same suspect malicous code as Simplecalc.exe."
                author="Benjamin Ware"
                date="2025-10-04"
                threatfamily="Thug Lyfe"
        
        strings:
                $thuglyfe = "165.73.244.11/installers"

        condition:
                $thuglyfe
}