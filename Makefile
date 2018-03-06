.PHONY: all clean

all: cinder

cinder:
	if [ ! -d ./vendor ]; then dep ensure; fi
	go build -i -o _bin/cdd

clean:
	go clean -r -x
	-rm -rf _bin/*
