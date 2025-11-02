#!/bin/bash
#This replaces the REPLACE with the extension in the test file
while read f; do
	f="${f:1}"
	sed "s/REPLACE/$f/" template.yar > "$f.yar"
done <TestTextFile.txt
