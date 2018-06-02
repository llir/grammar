# BNF of LLVM IR assembly grammar

[ll.bnf](ll.bnf)

## Modules

`01_modules.bnf`

* Source filename
* Target definitions
* Module-level inline assembly
* Type definitions
* Comdat definitions
* Global variables
* Indirect symbols
* Functions
* Attribute group definitions
* Metadata definitions
* Use-list order directives

## Identifiers

`02_identifiers.bnf`

* Global identifiers
* Local identifiers
* Label identifiers
* Attribute group identifiers
* Comdat identifiers
* Metadata identifiers

## Types

`03_types.bnf`

* Void type
* Function type
* Integer type
* Floating-point type
* Pointer type
* Vector type
* Label type
* Array type
* Struct type
* Named type
* MMX type
* Metadata type

## Values

`04_values.bnf`

* Constants
* Local identifiers
* Inline assembler expressions

## Constants

`05_constants.bnf`

* Boolean constants
* Integer constants
* Floating-point constants
* Null pointer constants
* Token constants
* Structure constants
* Array constants
* Vector constants
* Zero initialization constants
* Global identifiers
* Undefined values
* Addresses of basic blocks
* Constant expressions

## Constant expressions

`06_constant_expressions.bnf`

* Binary expressions
* Bitwise expressions
* Vector expressions
* Aggregate expressions
* Memory expressions
* Conversion expressions
* Other expressions

## Basic blocks

`07_basic_blocks.bnf`

## Instructions

`08_instructions.bnf`

* Binary instructions
* Bitwise instructions
* Vector instructions
* Aggregate  instructions
* Memory instructions
* Conversion instructions
* Other instructions

## Terminators

`09_terminators.bnf`

## Metadata

* Metadata tuples
* metadata
* Metadata strings
* Metadata attachments
* Metadata nodes
* Specialized metadata nodes
