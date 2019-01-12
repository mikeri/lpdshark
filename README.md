# lpdshark
Extract LPR/LPD print jobs from wireshark capture files.

## Usage
```
./lpdshark.py -p <output path> -o <base output filename> <capture file>
```
### Arguments
- `-p, --outpath DIR`:      Output path to save print jobs in. Default is current directory.
- `-o, --outfile FILENAME`: Base file name for saved print jobs. If not specified, lpdshark will
                            attempt to extract the filename from the print job.
- `-s, --sequence`:         Add wireshark sequence number to file name.

### Examples
Save print jobs from printcapture.pcap to a directory called "out".
```
./lpdshark.py -p out printcapture.pcap
```
Save print jobs named printjob-0.prn, printjob-1.prn etc. to a directory called "pcl". 
```
./lpdshark.py -s -p pcl -o printjob printcapture.pcap
```

## Requirements
- Python 3.6+
- pyshark
- tshark

### pyshark
`$ pip3 install --user pyshark`
### tshark
On Ubuntu and Debian:
`# apt install tshark`

## Convert extracted jobs to PDF
In order to view the print jobs you might want to convert them to PDF files. Postscript
print jobs can be converted with ps2pdf from ghostscript, and PCL jobs can be converted
with GhostPCL. (https://ghostscript.com/download/gpcldnld.html)

For converting many PCL files, the pcl2pdf.sh script can be used:
`./pcl2pdf.sh prn pdf` will convert all PCL files in the "prn" directory to PDF files to
the "pdf" directory. The script uses GNU Parallel as generating raster from PCL files ca
be CPU intensive.
