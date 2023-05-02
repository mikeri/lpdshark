#!/usr/bin/python3
import re
import os
import pyshark
import argparse
import subprocess

parser = argparse.ArgumentParser(description="Extract LPR/LPD print job(s) from wireshark capture file")
parser.add_argument('file', help="Capture file")
parser.add_argument('--debug', 
                  action='store_true',
                  help="Print debug info.")
parser.add_argument('-p' ,'--outpath', 
                  default=None,
                  help="Output path to write to. If omitted, use current directory.")
parser.add_argument('-s' ,'--sequence', 
                  default=False,
                  action='store_true',
                  help="Add capture sequence number to file name.")
parser.add_argument('-o' ,'--outfile', 
                  default=None,
                  help="Output file name. If omitted, use print job name.")
parser.add_argument('-v', '--version',
                  action='version',
                  version="lprshark 0.1 by Michael Ilsaas")
args = parser.parse_args()
try:
    cap = pyshark.FileCapture(args.file, include_raw=True, use_json=True)
except IOError:
    print(f"Reading capture file {args.file} failed")
    exit()

def debug(message):
    if args.debug:
        print(message)

def status(message):
    rows, columns = os.popen('stty size', 'r').read().split()
    spaces = int(rows) - len(message)
    print(message, flush=True, end=' ' * spaces + '\r')

def main():
    job = 0
    stream = -1
    output = subprocess.run(f'tshark -r {args.file} | wc -l', shell=True, stdout=subprocess.PIPE)
    length = int(output.stdout)
    for i, packet in enumerate(cap):
        percent = int(i / (length) * 100) if length > 0 else 100
        if not (i+1) % 10:
            status(f"Parsing: {percent}% done. Jobs found: {job}")
        if hasattr(packet, 'lpd') and stream != int(packet.tcp.stream):
            stream = int(packet.tcp.stream)
            job += 1
            job_data = get_job(i, stream, percent, job, length)
            base_name = args.outfile
            if not base_name:
                base_name = pjl_attribute(job_data, 'S?E?T?\s?JOB\s?NAME', default="printjob")
            if args.sequence:
                sequence = '-' + str(stream)
            else:
                sequence = ''
            file_name = base_name + sequence + ".prn"
            if args.outpath:
                file_path = os.path.join(args.outpath, file_name)
            else:
                file_path = file_name
            try:
                job_file = open(file_path, 'wb')
            except FileNotFoundError:
                os.mkdir(args.outpath)
                job_file = open(file_path, 'wb')
            except NotADirectoryError:
                print(f'Error: Specified output path "{args.outpath}" is not a directory.')
                exit()
            job_file.write(job_data)
            job_file.close()
            print("Saved " + file_path + "                                    ", flush=True)
            debug(f"Packet: {i} - Length: {len(job_data)}")
    print(f"Done! {job} jobs found.              ")

def pjl_attribute(job_data, attribute, **kwargs):
    value = re.search('\\@PJL ' + attribute + '\s*=\s*"(.+?)"', job_data.decode('ascii', 'ignore'))
    if value:
        return value[1]
    elif kwargs['default']:
        return kwargs['default']
    else:
        return None

def end_of_job(packet, stream):
    try:
        if stream != int(packet.tcp.stream):
            return False
        debug("Packet flags:" + packet.tcp.flags)
        return int(packet.tcp.flags, 16) & 1
    except Exception:
        return False

def get_job(position, stream, percent, job, length):
    status(f"Parsing: {percent}% done. Jobs found: {job} Extracting job...")
    header = True
    packet = cap[position]
    job_data = ''
    while not end_of_job(packet, stream) and position <= length:
        position += 1
        debug(f"Packet number: {position}")
        if hasattr(packet, 'lpd') and int(packet.tcp.stream) == stream:
            debug("LPD packet found.")
            debug(stream)
            debug(int(packet.tcp.stream))
            if stream == int(packet.tcp.stream) and hasattr(packet.tcp, 'payload_raw'):
                debug(packet.tcp.payload_raw)
                data = packet.tcp.payload_raw[0]
                if packet.tcp.dstport == '515' and not header:
                    job_data += data
                if data[:2] == '03' and header:
                    header = False
        packet = cap[position]
    return bytes.fromhex(job_data)

main()
