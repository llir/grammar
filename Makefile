all: ll.bnf

ll.bnf: sections/lex.bnf sections/syntax.bnf
	cat $^ > $@

sections/syntax.bnf: sections/01_modules.bnf sections/02_identifiers.bnf sections/03_types.bnf sections/04_values.bnf sections/05_constants.bnf sections/06_constant_expressions.bnf sections/07_basic_blocks.bnf sections/08_instructions.bnf sections/09_terminators.bnf sections/10_helpers.bnf
	cat $^ > $@

sections/01_modules.bnf: sections/01_modules/a_summary.bnf sections/01_modules/b_source_filename.bnf sections/01_modules/c_target_specifiers.bnf sections/01_modules/d_type_definitions.bnf sections/01_modules/e_global_variables.bnf sections/01_modules/f_functions.bnf sections/01_modules/g_attribute_group_definitions.bnf sections/01_modules/h_metadata_definitions.bnf
	cat $^ > $@

sections/06_constant_expressions.bnf: sections/06_constant_expressions/a_summary.bnf sections/06_constant_expressions/b_binary_expressions.bnf sections/06_constant_expressions/c_bitwise_expressions.bnf sections/06_constant_expressions/d_vector_expressions.bnf sections/06_constant_expressions/e_aggregate_expressions.bnf sections/06_constant_expressions/f_memory_expressions.bnf sections/06_constant_expressions/g_conversion_expressions.bnf sections/06_constant_expressions/h_other_expressions.bnf
	cat $^ > $@

sections/08_instructions.bnf: sections/08_instructions/a_summary.bnf sections/08_instructions/b_binary_instructions.bnf sections/08_instructions/c_bitwise_instructions.bnf sections/08_instructions/d_vector_instructions.bnf sections/08_instructions/e_aggregate_instructions.bnf sections/08_instructions/f_memory_instructions.bnf sections/08_instructions/g_conversion_instructions.bnf sections/08_instructions/h_other_instructions.bnf
	cat $^ > $@

clean:
	rm -f ll.bnf sections/syntax.bnf sections/01_modules.bnf sections/06_constant_expressions.bnf sections/08_instructions.bnf

.PHONY: all clean
