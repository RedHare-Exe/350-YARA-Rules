import "pe"

rule disguisedExeCheck
{
  meta:
    description = "Checks to see if non executables files contain elements of an executable file."
    author = "Benjamin Ware"
    date = "2025-09-19"

  strings:
    $exeHeader = { 4D 5A }
    $executableText = "!This program cannot be run in DOS mode."

  condtions:
    executable > 0 and
    exeHeader
}
