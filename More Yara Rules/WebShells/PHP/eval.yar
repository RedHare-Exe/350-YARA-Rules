rule eval
{
    meta:
    description = "Checks if a file contains the PHP eval() command."
    author = "Benjamin McKeever"
    date = "2025-10-27"

    strings:
    $var1 = "eval("

    condition:
    $var1
}
