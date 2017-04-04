all: ll.bnf

ll.bnf: lex.bnf syntax.bnf
	cat $^ > $@

syntax.bnf: 01_modules.bnf 02_identifiers.bnf 03_types.bnf 04_values.bnf 05_constants.bnf 06_constant_expressions.bnf 07_basic_blocks.bnf 08_instructions.bnf 09_terminators.bnf
	cat $^ > $@

08_instructions.bnf: 08_instructions/a_summary.bnf 08_instructions/b_binary_instructions.bnf 08_instructions/c_bitwise_instructions.bnf 08_instructions/d_vector_instructions.bnf 08_instructions/e_aggregate_instructions.bnf 08_instructions/f_memory_instructions.bnf 08_instructions/g_conversion_instructions.bnf 08_instructions/h_other_instructions.bnf
	cat $^ > $@

clean:
	rm -f ll.bnf syntax.bnf 08_instructions.bnf


.PHONY: all clean
