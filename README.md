## TShark Extractor Usage

TShark is the command line tool for WireShark. It doesn't ship with a file extractor, which is why this script exists.

Learn more about TShark: https://www.wireshark.org/docs/man-pages/tshark.html

### Instructions for Use

Run the script by specifying an input file with -i:
`python thsark_extractor.py -i myfile.pcap`

You may also specify an output file with -o, and a display filter with -D.

Learn more about display filters: https://wiki.wireshark.org/DisplayFilters


