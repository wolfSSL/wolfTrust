.DEFAULT_GOAL := all
include ../common/common.am
include build/order.mk

SRC := src
PDF := wolfTrust-Manual.pdf

.PHONY: all html-prep pdf-prep
all: pdf html

html-prep:
	@true

pdf-prep:
	python3 "$(WT_SOURCE)/tools/docs_manual.py" pdf-links --documentation-root ..
