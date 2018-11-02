all: ll.bnf

ll.bnf: sections/lex.bnf sections/syntax.bnf
	cat $^ > $@

sections/syntax.bnf: sections/01_module.bnf sections/02_identifier.bnf sections/03_type.bnf sections/04_value.bnf sections/05_constant.bnf sections/06_constant_expression.bnf sections/07_basic_block.bnf sections/08_instruction.bnf sections/09_terminator.bnf sections/10_metadata.bnf sections/11_helper.bnf
	cat $^ > $@

sections/01_module.bnf: sections/01_module/a_summary.bnf sections/01_module/b_source_filename.bnf sections/01_module/c_target_definition.bnf sections/01_module/d_module_asm.bnf sections/01_module/e_type_definition.bnf sections/01_module/f_comdat_definition.bnf sections/01_module/g_global_variable.bnf sections/01_module/h_indirect_symbol.bnf sections/01_module/i_function.bnf sections/01_module/j_attribute_group_definition.bnf sections/01_module/k_metadata_definition.bnf sections/01_module/l_use_list.bnf
	cat $^ > $@

sections/06_constant_expression.bnf: sections/06_constant_expression/a_summary.bnf sections/06_constant_expression/b_binary_expression.bnf sections/06_constant_expression/c_bitwise_expression.bnf sections/06_constant_expression/d_vector_expression.bnf sections/06_constant_expression/e_aggregate_expression.bnf sections/06_constant_expression/f_memory_expression.bnf sections/06_constant_expression/g_conversion_expression.bnf sections/06_constant_expression/h_other_expression.bnf
	cat $^ > $@

sections/08_instruction.bnf: sections/08_instruction/a_summary.bnf sections/08_instruction/b_binary_instruction.bnf sections/08_instruction/c_bitwise_instruction.bnf sections/08_instruction/d_vector_instruction.bnf sections/08_instruction/e_aggregate_instruction.bnf sections/08_instruction/f_memory_instruction.bnf sections/08_instruction/g_conversion_instruction.bnf sections/08_instruction/h_other_instruction.bnf
	cat $^ > $@

sections/10_metadata.bnf: sections/10_metadata/a_summary.bnf sections/10_metadata/b_specialized_metadata_node.bnf sections/10_metadata/c_debug_info.bnf
	cat $^ > $@

clean:
	rm -f ll.bnf sections/syntax.bnf sections/01_module.bnf sections/06_constant_expression.bnf sections/08_instruction.bnf sections/10_metadata.bnf
	rm -rf errors lexer parser token util
	rm -f LR1_conflicts.txt LR1_sets.txt first.txt lexer_sets.txt terminals.txt

.PHONY: all gen clean
