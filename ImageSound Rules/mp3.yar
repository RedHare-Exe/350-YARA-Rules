rule MP3_ID{
    meta:
        description = "Idetifies a file as an MP3"
        author = "Ellis Tomsen"

    strings:
        $mp3_header_1 = {49 44 33}
        $mp3_header_2 = {FF E?}
        $mp3_header_3 = {FF F?}

    condition:
       ($mp3_header_1 at 0) or ($mp3_header_2 at 0) or ($mp3_header_3 at 0)
}