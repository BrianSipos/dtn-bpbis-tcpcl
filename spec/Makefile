
%.xml: %.top.xml include-and-strip.xsl *.yang
	xsltproc --output $@ --xinclude include-and-strip.xsl $<

%.txt: %.xml
	xml2rfc -o $@ $<

%.html: %.xml
	xml2rfc --html -o $@ $<

OUTFILES = \
	draft-ietf-dtn-tcpclv4.html \
	draft-ietf-dtn-tcpclv4.txt

all: $(OUTFILES)

clean:
	rm $(OUTFILES)
