all: ll.bnf

ll.bnf: lex.bnf syntax.bnf
	cat $^ > $@

.PHONY: all
