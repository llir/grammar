all: ll.bnf

ll.bnf: lex.bnf syntax.bnf
	cat $^ > $@

syntax.bnf: 01_modules.bnf 02_identifiers.bnf 03_types.bnf 04_values.bnf 05_constants.bnf 06_constant_expressions.bnf 07_basic_blocks.bnf 08_instructions.bnf 09_terminators.bnf
	cat $^ > $@

.PHONY: all
