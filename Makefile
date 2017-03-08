run: build
	sudo ./ET4397IN

build:
	go build

%.pdf: %.md
	pandoc --variable urlcolor=cyan $< -o $@

%.html: %.md
	pandoc $< -o $@

clean:
	rm -f $(wildcard doc/*.md)

.PHONY: run build clean
