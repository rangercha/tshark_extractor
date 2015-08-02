#!/usr/bin/python
import string;
import binascii;
import sys;
import argparse;
import gzip;
try:
  from cStringIO import StringIO;
except:
  from StringIO import StringIO;
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
  hex_stream_data_list = check_output(["tshark", "-r", infile, "-Y", "(" + build_stream_filter(matching_streams_list) + ") && " + displayfilter + " && http.content_length > 0", "-T", "fields", "-e", "tcp.reassembled.data", "-e", "tcp.stream"]).split();

  #extract the stream numbers from the returned list
  ordered_stream_list=[];
  raw_data_list=[];
  found_flag=0;

  #tshark returns stream numbers with no data sometimes. so we'll find the items with hex encoded data and convert them to their normal binary values.
  #when only take the stream info that immediately follows the data to avoid the extraneous items.
  for matching_item in tshark_return_data_list:
  #hex-encoded data > 1 byte will have a : in it.
    if not ":" in matching_item:
    #not hex-encoded
      if found_flag==1:  
      #ensure we're immediately following an actual data item
        ordered_stream_list.append(matching_item);
        found_flag=0;
    else:
    #code path for hex entries
      matching_item=binascii.unhexlify(matching_item.replace(":",""));
      #find the end of the response header. This should always be \r\n\r\n to satisfy the HTTP standard
      end_of_header=matching_item.index('\r\n\r\n')+4;
      if 'Content-Encoding: gzip' in matching_item[:end_of_header]:
      #Content-Encoding header indicates gzipped content. try to uncompress
        buf=StringIO(matching_item[end_of_header:]);
        f = gzip.GzipFile(fileobj=buf);
        matching_item = f.read();
      else:
      #not gzipped, just grab the response body
        matching_item = matching_item[end_of_header:];

      #add the resultant value to the output list
      raw_data_list.append(matching_item);
      found_flag=1;

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
