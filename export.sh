#!/bin/bash
echo "" > source.txt
files=$(ls *.c *.h | sort)
for file in $files; do
    echo "----- $file -----" >> source.txt
    cat "$file" >> source.txt
    echo -e "\n\n" >> source.txt
done
echo "Exported all .c and .h files to source.txt."
