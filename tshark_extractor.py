#!/usr/bin/python
import string;
import binascii;
import sys;
import argparse;
from subprocess import check_output;

#or filters for all the streams together. 
def build_stream_filter(stream_list):
  return 'tcp.stream eq ' + ' || tcp.stream eq '.join(stream_list);

#extract files matching the specified display filter from the pcap file specified in "infile"
#place them in the "outdir" directory.

def extract_files(outdir, infile, displayfilter):
#extract all the stream numbers containing the specified display filter
  matching_streams_list = check_output(["tshark", "-r", infile, "-Y", displayfilter, "-T", "fields", "-e", "tcp.stream"]).split();
  matching_streams_list = list(set(matching_streams_list));
#sometimes tshark returns the nonsensical tcp stream of 0. 
  try:
    matching_streams_list.remove("0");
  except:
    pass  
#now we re-run the tshark query with the list of streams in the display filter.
#return stream numbers and the reassembled data. we'll use the stream number in the file name so it can be found in wireshark later if necessary
  hex_stream_data_list = check_output(["tshark", "-r", infile, "-Y", "(" + build_stream_filter(matching_streams_list) + ") && " + displayfilter, "-T", "fields", "-e", "tcp.stream", "-e", "tcp.reassembled.data"]).split();

#extract the stream numbers from the returned list
  ordered_stream_list=[];
  for stream_index in xrange(0,len(hex_stream_data_list),2):
    ordered_stream_list.append(hex_stream_data_list[stream_index]);

#remove the stream numbers from the returned list
  for stream_index in ordered_stream_list:
    hex_stream_data_list.remove(stream_index);

#convert the hex-encoded data back to binary
  raw_data_list = [binascii.unhexlify(hex_stream_data.replace(":","")) for hex_stream_data in hex_stream_data_list];
#the reassembled stream data contains the response headers. Remove everything up to the first \r\n\r\n sequence.
  raw_data_list = [raw_data[raw_data.index('\r\n\r\n')+4:] for raw_data in raw_data_list];

#take the raw bytes and write them out to files.
  for file_index, file_bytes in enumerate(raw_data_list):
    fh=open(outdir + 'stream_'+ordered_stream_list[file_index]+'_'+str(file_index),'w');
    fh.write(file_bytes);
    fh.close();


def main(args):
  parser = argparse.ArgumentParser();
  parser.add_argument('-o', '--outdir', default='./');
  parser.add_argument('-i', '--infile');
  parser.add_argument('-D', '--displayfilter');
  args = parser.parse_args();

  if not args.infile:
    parser.error('Missing input file argument.');
  
  if not args.displayfilter:
    parser.error('Missing display filter argument.');

  extract_files(vars(args)['outdir'], vars(args)['infile'], vars(args)['displayfilter']);


if __name__ == "__main__":
  main(sys.argv[1:]);
