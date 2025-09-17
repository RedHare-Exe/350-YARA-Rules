import "math"

rule entropyover7 {
    meta:
        author="Benjamin McKeever"
		description="Tests if a file has an entropy higher than 7."
		date="2025-09-16" 

    condition:
        math.entropy(0, filesize) >= 7
}