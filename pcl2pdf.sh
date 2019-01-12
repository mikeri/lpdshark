#!/bin/bash
find $1/*.prn -printf '%f\n' | parallel -I {} gpcl6 -o $2/{}.pdf -sDEVICE=pdfwrite $1/{}
