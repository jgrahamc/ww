NAME       := ww

include gmsl/gmsl

PWD := $(shell pwd)

.PHONY: all
all: ww

.PHONY: ww
ww: bin/$(NAME)

.PHONY: bin/$(NAME)
bin/$(NAME): ; @GOPATH="${PWD}" go install ww

.PHONY: clean
clean:
	GOPATH="${PWD}" go clean
