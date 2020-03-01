
%.xml: %.top.xml include-and-strip.xsl *.yang
	xsltproc --output $@ --xinclude include-and-strip.xsl $<

%.txt: %.xml
	xml2rfc -o $@ $<

%.html: %.xml
	xml2rfc --html -o $@ $<

%.cwl: %.txt
	cat $< | aspell --lang=en create master ./$@
misspelling.txt: draft-ietf-dtn-tcpclv4.xml dictionary.cwl
	cat draft-ietf-dtn-tcpclv4.xml | aspell --mode=sgml --lang=EN_US --extra-dicts=./dictionary.cwl list | sort | uniq >misspelling.txt

OUTFILES = \
	draft-ietf-dtn-tcpclv4.html \
	draft-ietf-dtn-tcpclv4.txt \
	misspelling.txt

all: $(OUTFILES)

clean:
	rm $(OUTFILES)
