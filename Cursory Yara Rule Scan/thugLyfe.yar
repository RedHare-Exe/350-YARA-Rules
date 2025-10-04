import "pe"

rule matchesDasuwerugwuerwq
{
        meta: 
            description= "Finds files that are similar to the dasuwerugwuerwq.exe file."
            author="Benjamin McKeever"
            date="2025-10-03"
            threatfamily="Thug Lyfe"

        strings:
            $thuglyfe = "thug.lyfe"

        condition:
            $thuglyfe
}

//next rule starts here