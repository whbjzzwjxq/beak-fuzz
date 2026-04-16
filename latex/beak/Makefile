TEX = pdflatex -interaction=nonstopmode
BIB = bibtex
MAIN = main

.PHONY: all clean

all:
	$(TEX) $(MAIN).tex
	$(BIB) $(MAIN)
	$(TEX) $(MAIN).tex
	$(TEX) $(MAIN).tex

clean:
	rm -f $(MAIN).aux $(MAIN).bbl $(MAIN).blg $(MAIN).log $(MAIN).out $(MAIN).pdf $(MAIN).toc $(MAIN).lof $(MAIN).lot $(MAIN).run.xml $(MAIN).bcf $(MAIN).synctex.gz
