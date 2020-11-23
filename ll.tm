language llvm(go);

lang = "llvm"
package = "github.com/llir/ll"
eventBased = true
eventFields = true
eventAST = true

# TODO: check when to use Fooopt and when to use Foo? (as based on the AST
# they produce)

# ### [ Lexical part ] #########################################################

:: lexer

_ascii_letter_upper = /[A-Z]/

_ascii_letter_lower = /[a-z]/

_ascii_letter = /{_ascii_letter_upper}|{_ascii_letter_lower}/

_letter = /{_ascii_letter}|[-$\._]/

_escape_letter = /{_letter}|[\\]/

_decimal_digit = /[0-9]/

_hex_digit = /{_decimal_digit}|[A-Fa-f]/

comment : /[;][^\r\n]*/               (space)
whitespace : /[\x00 \t\r\n]+/         (space)

# === [ Identifiers ] ==========================================================

_name = /{_letter}({_letter}|{_decimal_digit})*/

_escape_name = /{_escape_letter}({_escape_letter}|{_decimal_digit})*/

_quoted_name = /{_quoted_string}/

_id = /{_decimals}/

# --- [ Global identifiers ] ---------------------------------------------------

global_ident_tok : /{_global_name}|{_global_id}/

_global_name = /[@]({_name}|{_quoted_name})/

_global_id = /[@]{_id}/

# --- [ Local identifiers ] ----------------------------------------------------

local_ident_tok : /{_local_name}|{_local_id}/

_local_name = /[%]({_name}|{_quoted_name})/

_local_id = /[%]{_id}/

# --- [ Labels ] ---------------------------------------------------------------

#   Label             [-a-zA-Z$._0-9]+:

label_ident_tok : /(({_letter}|{_decimal_digit})({_letter}|{_decimal_digit})*[:])|({_quoted_string}[:])/   (class)

# --- [ Attribute group identifiers ] ------------------------------------------

attr_group_id_tok : /[#]{_id}/

# --- [ Comdat identifiers ] ---------------------------------------------------

comdat_name_tok : /[$]({_name}|{_quoted_name})/

# --- [ Metadata identifiers ] -------------------------------------------------

metadata_name_tok : /[!]{_escape_name}/   (class)

metadata_id_tok : /[!]{_id}/

# DW_TAG_foo
dwarf_tag_tok : /DW_TAG_({_ascii_letter}|{_decimal_digit}|[_])*/

# DW_ATE_foo
dwarf_att_encoding_tok : /DW_ATE_({_ascii_letter}|{_decimal_digit}|[_])*/

# DIFlagFoo
di_flag_tok : /DIFlag({_ascii_letter}|{_decimal_digit}|[_])*/

# DISPFlagFoo
disp_flag_tok : /DISPFlag({_ascii_letter}|{_decimal_digit}|[_])*/

# DW_LANG_foo
dwarf_lang_tok : /DW_LANG_({_ascii_letter}|{_decimal_digit}|[_])*/

# DW_CC_foo
dwarf_cc_tok : /DW_CC_({_ascii_letter}|{_decimal_digit}|[_])*/

# CSK_foo
checksum_kind_tok : /CSK_({_ascii_letter}|{_decimal_digit}|[_])*/

# DW_VIRTUALITY_foo
dwarf_virtuality_tok : /DW_VIRTUALITY_({_ascii_letter}|{_decimal_digit}|[_])*/

# DW_MACINFO_foo
dwarf_macinfo_tok : /DW_MACINFO_({_ascii_letter}|{_decimal_digit}|[_])*/

# DW_OP_foo
dwarf_op_tok : /DW_OP_({_ascii_letter}|{_decimal_digit}|[_])*/

# ref: DWKEYWORD

# FullDebug
emission_kind_tok : /(DebugDirectivesOnly)|(FullDebug)|(LineTablesOnly)|(NoDebug)/

# GNU
name_table_kind_tok : /(GNU)|(None)|(Default)/

# === [ Integer literals ] =====================================================

#   Integer           [-]?[0-9]+
#   HexIntConstant    [us]0x{_hex_digit}+

int_lit_tok : /[-]?[0-9]+|{_int_hex_lit}/

_int_hex_lit = /[us]0x{_hex_digit}+/

_decimals = /{_decimal_digit}+/

# === [ Floating-point literals ] ==============================================

#   FPConstant        [-+]?[0-9]+[.][0-9]*([eE][-+]?[0-9]+)?

float_lit_tok : /{_frac_lit}|{_sci_lit}|{_float_hex_lit}/

_frac_lit = /{_sign}?{_decimals}[\.]{_decimal_digit}*/

_sign = /[+-]/

_sci_lit = /{_frac_lit}[eE]{_sign}?{_decimals}/

#   HexFPConstant     0x{_hex_digit}+     // 16 hex digits
#   HexFP80Constant   0xK{_hex_digit}+    // 20 hex digits
#   HexFP128Constant  0xL{_hex_digit}+    // 32 hex digits
#   HexPPC128Constant 0xM{_hex_digit}+    // 32 hex digits
#   HexHalfConstant   0xH{_hex_digit}+    // 4 hex digits

_float_hex_lit = /0x[KLMH]?{_hex_digit}+/

# === [ String literals ] ======================================================

string_lit_tok : /{_quoted_string}/

_quoted_string = /["][^"]*["]/

# === [ Types ] ================================================================

int_type_tok : /i[0-9]+/

# List of tokens is sorted alphabetically.

'aarch64_sve_vector_pcs' : /aarch64_sve_vector_pcs/
'aarch64_vector_pcs' : /aarch64_vector_pcs/
'acq_rel' : /acq_rel/
'acquire' : /acquire/
'add' : /add/
'addrspace' : /addrspace/
'addrspacecast' : /addrspacecast/
'afn' : /afn/
'alias' : /alias/
'align' : /align/
'alignstack' : /alignstack/
'alloca' : /alloca/
'allocsize' : /allocsize/
'alwaysinline' : /alwaysinline/
'amdgpu_cs' : /amdgpu_cs/
'amdgpu_es' : /amdgpu_es/
'amdgpu_gs' : /amdgpu_gs/
'amdgpu_hs' : /amdgpu_hs/
'amdgpu_kernel' : /amdgpu_kernel/
'amdgpu_ls' : /amdgpu_ls/
'amdgpu_ps' : /amdgpu_ps/
'amdgpu_vs' : /amdgpu_vs/
'and' : /and/
'any' : /any/
'anyregcc' : /anyregcc/
'appending' : /appending/
'arcp' : /arcp/
'argmemonly' : /argmemonly/
'arm_aapcs_vfpcc' : /arm_aapcs_vfpcc/
'arm_aapcscc' : /arm_aapcscc/
'arm_apcscc' : /arm_apcscc/
'ashr' : /ashr/
'asm' : /asm/
'atomic' : /atomic/
'atomicrmw' : /atomicrmw/
'attributes' : /attributes/
'available_externally' : /available_externally/
'avr_intrcc' : /avr_intrcc/
'avr_signalcc' : /avr_signalcc/
'bitcast' : /bitcast/
'blockaddress' : /blockaddress/
'blockcount': /blockcount/
'br' : /br/
'builtin' : /builtin/
'byval' : /byval/
'c' : /c/
'call' : /call/
'callbr' : /callbr/
'caller' : /caller/
'catch' : /catch/
'catchpad' : /catchpad/
'catchret' : /catchret/
'catchswitch' : /catchswitch/
'cc' : /cc/
'ccc' : /ccc/
'cfguard_checkcc' : /cfguard_checkcc/
'cleanup' : /cleanup/
'cleanuppad' : /cleanuppad/
'cleanupret' : /cleanupret/
'cmpxchg' : /cmpxchg/
'cold' : /cold/
'coldcc' : /coldcc/
'comdat' : /comdat/
'common' : /common/
'constant' : /constant/
'contract' : /contract/
'convergent' : /convergent/
'cxx_fast_tlscc' : /cxx_fast_tlscc/
'datalayout' : /datalayout/
'declare' : /declare/
'default' : /default/
'define' : /define/
'dereferenceable' : /dereferenceable/
'dereferenceable_or_null' : /dereferenceable_or_null/
'distinct' : /distinct/
'dllexport' : /dllexport/
'dllimport' : /dllimport/
'double' : /double/
'dso_local' : /dso_local/
'dso_preemptable' : /dso_preemptable/
'eq' : /eq/
'exact' : /exact/
'exactmatch' : /exactmatch/
'extern_weak' : /extern_weak/
'external' : /external/
'externally_initialized' : /externally_initialized/
'extractelement' : /extractelement/
'extractvalue' : /extractvalue/
'fadd' : /fadd/
'false' : /false/
'fast' : /fast/
'fastcc' : /fastcc/
'fcmp' : /fcmp/
'fdiv' : /fdiv/
'fence' : /fence/
'filter' : /filter/
'float' : /float/
'fmul' : /fmul/
'fneg' : /fneg/
'fp128' : /fp128/
'fpext' : /fpext/
'fptosi' : /fptosi/
'fptoui' : /fptoui/
'fptrunc' : /fptrunc/
'freeze' : /freeze/
'frem' : /frem/
'from' : /from/
'fsub' : /fsub/
'gc' : /gc/
'getelementptr' : /getelementptr/
'ghccc' : /ghccc/
'global' : /global/
'half' : /half/
'hhvm_ccc' : /hhvm_ccc/
'hhvmcc' : /hhvmcc/
'hidden' : /hidden/
'icmp' : /icmp/
'ifunc' : /ifunc/
'immarg' : /immarg/
'inaccessiblemem_or_argmemonly' : /inaccessiblemem_or_argmemonly/
'inaccessiblememonly' : /inaccessiblememonly/
'inalloca' : /inalloca/
'inbounds' : /inbounds/
'indirectbr' : /indirectbr/
'initialexec' : /initialexec/
'inlinehint' : /inlinehint/
'inrange' : /inrange/
'inreg' : /inreg/
'insertelement' : /insertelement/
'insertvalue' : /insertvalue/
'intel_ocl_bicc' : /intel_ocl_bicc/
'inteldialect' : /inteldialect/
'internal' : /internal/
'inttoptr' : /inttoptr/
'invoke' : /invoke/
'jumptable' : /jumptable/
'label' : /label/
'landingpad' : /landingpad/
'largest' : /largest/
'linkonce' : /linkonce/
'linkonce_odr' : /linkonce_odr/
'load' : /load/
'local_unnamed_addr' : /local_unnamed_addr/
'localdynamic' : /localdynamic/
'localexec' : /localexec/
'lshr' : /lshr/
'max' : /max/
'metadata' : /metadata/
'min' : /min/
'minsize' : /minsize/
'module' : /module/
'monotonic' : /monotonic/
'msp430_intrcc' : /msp430_intrcc/
'mul' : /mul/
'musttail' : /musttail/
'naked' : /naked/
'nand' : /nand/
'ne' : /ne/
'nest' : /nest/
'ninf' : /ninf/
'nnan' : /nnan/
'noalias' : /noalias/
'nobuiltin' : /nobuiltin/
'nocapture' : /nocapture/
'nocf_check' : /nocf_check/
'noduplicate' : /noduplicate/
'noduplicates' : /noduplicates/
'nofree' : /nofree/
'noimplicitfloat' : /noimplicitfloat/
'noinline' : /noinline/
'nomerge' : /nomerge/
'none' : /none/
'nonlazybind' : /nonlazybind/
'nonnull' : /nonnull/
'norecurse' : /norecurse/
'noredzone' : /noredzone/
'noreturn' : /noreturn/
'nosync' : /nosync/
'notail' : /notail/
'noundef': /noundef/
'nounwind' : /nounwind/
'nsw' : /nsw/
'nsz' : /nsz/
'null' : /null/
'null_pointer_is_valid': /null_pointer_is_valid/
'nuw' : /nuw/
'oeq' : /oeq/
'oge' : /oge/
'ogt' : /ogt/
'ole' : /ole/
'olt' : /olt/
'one' : /one/
'opaque' : /opaque/
'optforfuzzing' : /optforfuzzing/
'optnone' : /optnone/
'optsize' : /optsize/
'or' : /or/
'ord' : /ord/
'param' : /param/
'params' : /params/
'partition' : /partition/
'personality' : /personality/
'phi' : /phi/
'ppc_fp128' : /ppc_fp128/
'preallocated': /preallocated/
'prefix' : /prefix/
'preserve_allcc' : /preserve_allcc/
'preserve_mostcc' : /preserve_mostcc/
'private' : /private/
'prologue' : /prologue/
'protected' : /protected/
'ptrtoint' : /ptrtoint/
'ptx_device' : /ptx_device/
'ptx_kernel' : /ptx_kernel/
'readnone' : /readnone/
'readonly' : /readonly/
'reassoc' : /reassoc/
'release' : /release/
'resume' : /resume/
'ret' : /ret/
'returned' : /returned/
'returns_twice' : /returns_twice/
'safestack' : /safestack/
'samesize' : /samesize/
'sanitize_address' : /sanitize_address/
'sanitize_hwaddress' : /sanitize_hwaddress/
'sanitize_memory' : /sanitize_memory/
'sanitize_memtag' : /sanitize_memtag/
'sanitize_thread' : /sanitize_thread/
'sdiv' : /sdiv/
'section' : /section/
'select' : /select/
'seq_cst' : /seq_cst/
'sext' : /sext/
'sge' : /sge/
'sgt' : /sgt/
'shadowcallstack' : /shadowcallstack/
'shl' : /shl/
'shufflevector' : /shufflevector/
'sideeffect' : /sideeffect/
'signext' : /signext/
'singlethread' : /singlethread/
'sitofp' : /sitofp/
'sle' : /sle/
'slt' : /slt/
'source_filename' : /source_filename/
'speculatable' : /speculatable/
'speculative_load_hardening' : /speculative_load_hardening/
'spir_func' : /spir_func/
'spir_kernel' : /spir_kernel/
'srem' : /srem/
'sret' : /sret/
'ssp' : /ssp/
'sspreq' : /sspreq/
'sspstrong' : /sspstrong/
'store' : /store/
'strictfp' : /strictfp/
'sub' : /sub/
'swiftcc' : /swiftcc/
'swifterror' : /swifterror/
'swiftself' : /swiftself/
'switch' : /switch/
'syncscope' : /syncscope/
'tail' : /tail/
'tailcc' : /tailcc/
'target' : /target/
'thread_local' : /thread_local/
'to' : /to/
'token' : /token/
'triple' : /triple/
'true' : /true/
'trunc' : /trunc/
'type' : /type/
'udiv' : /udiv/
'ueq' : /ueq/
'uge' : /uge/
'ugt' : /ugt/
'uitofp' : /uitofp/
'ule' : /ule/
'ult' : /ult/
'umax' : /umax/
'umin' : /umin/
'undef' : /undef/
'une' : /une/
'unnamed_addr' : /unnamed_addr/
'uno' : /uno/
'unordered' : /unordered/
'unreachable' : /unreachable/
'unwind' : /unwind/
'urem' : /urem/
'uselistorder' : /uselistorder/
'uselistorder_bb' : /uselistorder_bb/
'uwtable' : /uwtable/
'va_arg' : /va_arg/
'vcall_visibility' : /vcall_visibility/
'void' : /void/
'volatile' : /volatile/
'vscale' : /vscale/
'weak' : /weak/
'weak_odr' : /weak_odr/
'webkit_jscc' : /webkit_jscc/
'willreturn' : /willreturn/
'win64cc' : /win64cc/
'within' : /within/
'writeonly' : /writeonly/
'x' : /x/
'x86_64_sysvcc' : /x86_64_sysvcc/
'x86_fastcallcc' : /x86_fastcallcc/
'x86_fp80' : /x86_fp80/
'x86_intrcc' : /x86_intrcc/
'x86_mmx' : /x86_mmx/
'x86_regcallcc' : /x86_regcallcc/
'x86_stdcallcc' : /x86_stdcallcc/
'x86_thiscallcc' : /x86_thiscallcc/
'x86_vectorcallcc' : /x86_vectorcallcc/
'xchg' : /xchg/
'xor' : /xor/
'zeroext' : /zeroext/
'zeroinitializer' : /zeroinitializer/
'zext' : /zext/

# Specialized metadata node names.
'!DIBasicType' : /!DIBasicType/
'!DICommonBlock' : /!DICommonBlock/
'!DICompileUnit' : /!DICompileUnit/
'!DICompositeType' : /!DICompositeType/
'!DIDerivedType' : /!DIDerivedType/
'!DIEnumerator' : /!DIEnumerator/
'!DIExpression' : /!DIExpression/
'!DIFile' : /!DIFile/
'!DIGlobalVariable' : /!DIGlobalVariable/
'!DIGlobalVariableExpression' : /!DIGlobalVariableExpression/
'!DIImportedEntity' : /!DIImportedEntity/
'!DILabel' : /!DILabel/
'!DILexicalBlock' : /!DILexicalBlock/
'!DILexicalBlockFile' : /!DILexicalBlockFile/
'!DILocalVariable' : /!DILocalVariable/
'!DILocation' : /!DILocation/
'!DIMacro' : /!DIMacro/
'!DIMacroFile' : /!DIMacroFile/
'!DIModule' : /!DIModule/
'!DINamespace' : /!DINamespace/
'!DIObjCProperty' : /!DIObjCProperty/
'!DISubprogram' : /!DISubprogram/
'!DISubrange' : /!DISubrange/
'!DISubroutineType' : /!DISubroutineType/
'!DITemplateTypeParameter' : /!DITemplateTypeParameter/
'!DITemplateValueParameter' : /!DITemplateValueParameter/
'!GenericDINode' : /!GenericDINode/

# Specialized metadata node field names.
'align:' : /align:/
'arg:' : /arg:/
'attributes:' : /attributes:/
'baseType:' : /baseType:/
'cc:' : /cc:/
'checksum:' : /checksum:/
'checksumkind:' : /checksumkind:/
'column:' : /column:/
'configMacros:' : /configMacros:/
'containingType:' : /containingType:/
'count:' : /count:/
'debugBaseAddress:' : /debugBaseAddress:/
'debugInfoForProfiling:' : /debugInfoForProfiling:/
'declaration:' : /declaration:/
'directory:' : /directory:/
'discriminator:' : /discriminator:/
'dwarfAddressSpace:' : /dwarfAddressSpace:/
'dwoId:' : /dwoId:/
'elements:' : /elements:/
'emissionKind:' : /emissionKind:/
'encoding:' : /encoding:/
'entity:' : /entity:/
'enums:' : /enums:/
'exportSymbols:' : /exportSymbols:/
'expr:' : /expr:/
'extraData:' : /extraData:/
'file:' : /file:/
'filename:' : /filename:/
'flags:' : /flags:/
'getter:' : /getter:/
'globals:' : /globals:/
'header:' : /header:/
'identifier:' : /identifier:/
'imports:' : /imports:/
'includePath:' : /includePath:/
'inlinedAt:' : /inlinedAt:/
'isDefinition:' : /isDefinition:/
'isImplicitCode:' : /isImplicitCode:/
'isLocal:' : /isLocal:/
'isOptimized:' : /isOptimized:/
'isUnsigned:' : /isUnsigned:/
'apinotes:' : /apinotes:/
'language:' : /language:/
'line:' : /line:/
'linkageName:' : /linkageName:/
'lowerBound:' : /lowerBound:/
'macros:' : /macros:/
'name:' : /name:/
'nameTableKind:' : /nameTableKind:/
'nodes:' : /nodes:/
'offset:' : /offset:/
'operands:' : /operands:/
'producer:' : /producer:/
'retainedNodes:' : /retainedNodes:/
'retainedTypes:' : /retainedTypes:/
'runtimeLang:' : /runtimeLang:/
'runtimeVersion:' : /runtimeVersion:/
'scope:' : /scope:/
'scopeLine:' : /scopeLine:/
'setter:' : /setter:/
'size:' : /size:/
'source:' : /source:/
'spFlags:' : /spFlags:/
'splitDebugFilename:' : /splitDebugFilename:/
'splitDebugInlining:' : /splitDebugInlining:/
'stride:' : /stride:/
'tag:' : /tag:/
'templateParams:' : /templateParams:/
'thisAdjustment:' : /thisAdjustment:/
'thrownTypes:' : /thrownTypes:/
'type:' : /type:/
'types:' : /types:/
'unit:' : /unit:/
'upperBound:' : /upperBound:/
'value:' : /value:/
'var:' : /var:/
'virtualIndex:' : /virtualIndex:/
'virtuality:' : /virtuality:/
'vtableHolder:' : /vtableHolder:/


',' : /[,]/
'!' : /[!]/
'...' : /\.\.\./
'(' : /[(]/
')' : /[)]/
'[' : /[\[]/
']' : /[\]]/
'{' : /[{]/
'}' : /[}]/
'*' : /[*]/
'<' : /[<]/
'=' : /[=]/
'>' : /[>]/
# TODO: use '|' (pipe_tok) : /[|]/ when https://github.com/inspirer/textmapper/issues/31 is resolved. See comments at https://github.com/inspirer/textmapper/pull/35#issuecomment-557939771
pipe_tok : /[|]/

# ### [ Syntax part ] ##########################################################

# The LLVM IR grammar has been based on the source code of the official LLVM
# project, version 7.0

:: parser

%input Module;

# === [ Identifiers ] ==========================================================

# --- [ Global Identifiers ] ---------------------------------------------------

GlobalIdent -> GlobalIdent
	: global_ident_tok
;

# --- [ Local Identifiers ] ----------------------------------------------------

LocalIdent -> LocalIdent
	: local_ident_tok
;

# --- [ Label Identifiers ] ----------------------------------------------------

LabelIdent -> LabelIdent
	: label_ident_tok
	# Specialized metadata node field names.
	| 'align:'
	| 'arg:'
	| 'attributes:'
	| 'baseType:'
	| 'cc:'
	| 'checksum:'
	| 'checksumkind:'
	| 'column:'
	| 'configMacros:'
	| 'containingType:'
	| 'count:'
	| 'debugInfoForProfiling:'
	| 'declaration:'
	| 'directory:'
	| 'discriminator:'
	| 'dwarfAddressSpace:'
	| 'dwoId:'
	| 'elements:'
	| 'emissionKind:'
	| 'encoding:'
	| 'entity:'
	| 'enums:'
	| 'exportSymbols:'
	| 'expr:'
	| 'extraData:'
	| 'file:'
	| 'filename:'
	| 'flags:'
	| 'getter:'
	| 'globals:'
	| 'header:'
	| 'identifier:'
	| 'imports:'
	| 'includePath:'
	| 'inlinedAt:'
	| 'isDefinition:'
	| 'isImplicitCode:'
	| 'isLocal:'
	| 'isOptimized:'
	| 'isUnsigned:'
	| 'apinotes:'
	| 'language:'
	| 'line:'
	| 'linkageName:'
	| 'lowerBound:'
	| 'macros:'
	| 'name:'
	| 'nameTableKind:'
	| 'nodes:'
	| 'offset:'
	| 'operands:'
	| 'producer:'
	| 'retainedNodes:'
	| 'retainedTypes:'
	| 'runtimeLang:'
	| 'runtimeVersion:'
	| 'scope:'
	| 'scopeLine:'
	| 'setter:'
	| 'size:'
	| 'source:'
	| 'splitDebugFilename:'
	| 'splitDebugInlining:'
	| 'tag:'
	| 'templateParams:'
	| 'thisAdjustment:'
	| 'thrownTypes:'
	| 'type:'
	| 'types:'
	| 'unit:'
	| 'value:'
	| 'var:'
	| 'virtualIndex:'
	| 'virtuality:'
	| 'vtableHolder:'
;

# --- [ Attribute Group Identifiers ] ------------------------------------------

AttrGroupID -> AttrGroupID
	: attr_group_id_tok
;

# --- [ Comdat Identifiers ] ---------------------------------------------------

ComdatName -> ComdatName
	: comdat_name_tok
;

# --- [ Metadata Identifiers ] -------------------------------------------------

MetadataName -> MetadataName
	: metadata_name_tok
;

MetadataID -> MetadataID
	: metadata_id_tok
;

# === [ Literals ] =============================================================

# --- [ Integer literals ] -----------------------------------------------------

BoolLit -> BoolLit
	: 'true'
	| 'false'
;

IntLit -> IntLit
	: int_lit_tok
;

UintLit -> UintLit
	: int_lit_tok
;

# --- [ Floating-point literals ] ----------------------------------------------

FloatLit -> FloatLit
	: float_lit_tok
;

# --- [ String literals ] ------------------------------------------------------

StringLit -> StringLit
	: string_lit_tok
;

# --- [ Null literals ] --------------------------------------------------------

NullLit -> NullLit
	: 'null'
;

# === [ Module ] ===============================================================

# https://llvm.org/docs/LangRef.html#module-structure

# ref: Run
#
#   module ::= toplevelentity*

Module -> Module
	: TopLevelEntities=TopLevelEntity*
;

# --- [ Top-level Entities ] ---------------------------------------------------

# ref: ParseTopLevelEntities

%interface TopLevelEntity;

TopLevelEntity -> TopLevelEntity
	: SourceFilename
	| TargetDef
	| ModuleAsm
	| TypeDef
	| ComdatDef
	| GlobalDecl
	| IndirectSymbolDef
	| FuncDecl
	| FuncDef
	| AttrGroupDef
	| NamedMetadataDef
	| MetadataDef
	| UseListOrder
	| UseListOrderBB
;

# ~~~ [ Source Filename ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#source-filename

# ref: ParseSourceFileName
#
#   ::= 'source_filename' '=' STRINGCONSTANT

SourceFilename -> SourceFilename
	: 'source_filename' '=' Name=StringLit
;

# ~~~ [ Target Definition ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#target-triple
# https://llvm.org/docs/LangRef.html#data-layout

# ref: ParseTargetDefinition
#
#   ::= 'target' 'triple' '=' STRINGCONSTANT
#   ::= 'target' 'datalayout' '=' STRINGCONSTANT

%interface TargetDef;

TargetDef -> TargetDef
	: TargetDataLayout
	| TargetTriple
;

TargetDataLayout -> TargetDataLayout
	: 'target' 'datalayout' '=' DataLayout=StringLit
;

TargetTriple -> TargetTriple
	: 'target' 'triple' '=' TargetTriple=StringLit
;

# ~~~ [ Module-level Inline Assembly ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#module-level-inline-assembly

# ref: ParseModuleAsm
#
#   ::= 'module' 'asm' STRINGCONSTANT

ModuleAsm -> ModuleAsm
	: 'module' 'asm' Asm=StringLit
;

# ~~~ [ Type Defintion ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#structure-type

# ref: ParseUnnamedType
#
#   ::= LocalVarID '=' 'type' type

# ref: ParseNamedType
#
#   ::= LocalVar '=' 'type' type

# TODO: Rename `Typ=` to `Type=` once https://github.com/inspirer/textmapper/issues/13
# is resolved.

TypeDef -> TypeDef
	: Name=LocalIdent '=' 'type' Typ=OpaqueType
	| Name=LocalIdent '=' 'type' Typ=Type
;

# ~~~ [ Comdat Definition ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#langref-comdats

# ref: parseComdat

ComdatDef -> ComdatDef
	: Name=ComdatName '=' 'comdat' Kind=SelectionKind
;

SelectionKind -> SelectionKind
	: 'any'
	| 'exactmatch'
	| 'largest'
	| 'noduplicates'
	| 'samesize'
;

# ~~~ [ Global Variable Declaration or Definition ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#global-variables

# ref: ParseUnnamedGlobal
#
#   OptionalVisibility (ALIAS | IFUNC) ...
#   OptionalLinkage OptionalPreemptionSpecifier OptionalVisibility
#   OptionalDLLStorageClass
#                                                     ...   -> global variable
#   GlobalID '=' OptionalVisibility (ALIAS | IFUNC) ...
#   GlobalID '=' OptionalLinkage OptionalPreemptionSpecifier OptionalVisibility
#                OptionalDLLStorageClass
#                                                     ...   -> global variable

# ref: ParseNamedGlobal
#
#   GlobalVar '=' OptionalVisibility (ALIAS | IFUNC) ...
#   GlobalVar '=' OptionalLinkage OptionalPreemptionSpecifier
#                 OptionalVisibility OptionalDLLStorageClass
#                                                     ...   -> global variable

# ref: ParseGlobal
#
#   ::= GlobalVar '=' OptionalLinkage OptionalPreemptionSpecifier
#       OptionalVisibility OptionalDLLStorageClass
#       OptionalThreadLocal OptionalUnnamedAddr OptionalAddrSpace
#       OptionalExternallyInitialized GlobalType Type Const OptionalAttrs
#   ::= OptionalLinkage OptionalPreemptionSpecifier OptionalVisibility
#       OptionalDLLStorageClass OptionalThreadLocal OptionalUnnamedAddr
#       OptionalAddrSpace OptionalExternallyInitialized GlobalType Type
#       Const OptionalAttrs

GlobalDecl -> GlobalDecl
	#: Name=GlobalIdent '=' Linkage=ExternLinkage Preemptionopt Visibilityopt DLLStorageClassopt ThreadLocalopt UnnamedAddropt AddrSpaceopt ExternallyInitializedopt Immutable ContentType=Type (',' Section)? (',' Partition)? (',' Comdat)? (',' Align)? Metadata=(',' MetadataAttachment)+? FuncAttrs=FuncAttribute+?
	#| Name=GlobalIdent '=' Linkage=Linkageopt Preemptionopt Visibilityopt DLLStorageClassopt ThreadLocalopt UnnamedAddropt AddrSpaceopt ExternallyInitializedopt Immutable ContentType=Type Init=Constant (',' Section)? (',' Partition)? (',' Comdat)? (',' Align)? Metadata=(',' MetadataAttachment)+? FuncAttrs=FuncAttribute+?
	: Name=GlobalIdent '=' Linkage=ExternLinkage Preemptionopt Visibilityopt DLLStorageClassopt ThreadLocalopt UnnamedAddropt AddrSpaceopt ExternallyInitializedopt Immutable ContentType=Type GlobalFields=(',' GlobalField)* Metadata=(',' MetadataAttachment)+? FuncAttrs=FuncAttribute+?
	| Name=GlobalIdent '=' Linkage=Linkageopt Preemptionopt Visibilityopt DLLStorageClassopt ThreadLocalopt UnnamedAddropt AddrSpaceopt ExternallyInitializedopt Immutable ContentType=Type Init=Constant GlobalFields=(',' GlobalField)* Metadata=(',' MetadataAttachment)+? FuncAttrs=FuncAttribute+?
;

# NOTE: GlobalField is a workaround to handle the LR-1 shift/reduce conflict
# between FuncAttribute and Align, both of which contain 'align'.

%interface GlobalField;

GlobalField -> GlobalField
	: Section
	| Partition
	| Comdat
	| Align
;

ExternallyInitialized -> ExternallyInitialized
	: 'externally_initialized'
;

# ref: ParseGlobalType
#
#   ::= 'constant'
#   ::= 'global'

Immutable -> Immutable
	: 'constant'
	| 'global'
;

# ~~~ [ Indirect Symbol Definition ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#aliases
# https://llvm.org/docs/LangRef.html#ifuncs

# ref: parseIndirectSymbol
#
#   ::= GlobalVar '=' OptionalLinkage OptionalPreemptionSpecifier
#                     OptionalVisibility OptionalDLLStorageClass
#                     OptionalThreadLocal OptionalUnnamedAddr
#                     'alias|ifunc' IndirectSymbol IndirectSymbolAttr*
#
#  IndirectSymbol
#   ::= TypeAndValue
#
#  IndirectSymbolAttr
#    ::= ',' 'partition' StringConstant

IndirectSymbolDef -> IndirectSymbolDef
	: Name=GlobalIdent '=' (ExternLinkage | Linkageopt) Preemptionopt Visibilityopt DLLStorageClassopt ThreadLocalopt UnnamedAddropt IndirectSymbolKind ContentType=Type ',' IndirectSymbol Partitions=(',' Partition)*
;

IndirectSymbolKind -> IndirectSymbolKind
	: 'alias'
	| 'ifunc'
;

%interface IndirectSymbol;

IndirectSymbol -> IndirectSymbol
	: TypeConst
	| BitCastExpr
	| GetElementPtrExpr
	| AddrSpaceCastExpr
	| IntToPtrExpr
;

# ~~~ [ Function Declaration ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#functions

# ref: ParseDeclare
#
#   ::= 'declare' FunctionHeader

FuncDecl -> FuncDecl
	: 'declare' Metadata=MetadataAttachment* Header=FuncHeader
;

# ~~~ [ Function Definition ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#functions

# ref: ParseDefine
#
#   ::= 'define' FunctionHeader (!dbg !56)* '{' ...

# ref: ParseOptionalFunctionMetadata
#
#   ::= (!dbg !57)*

FuncDef -> FuncDef
	: 'define' Header=FuncHeader Metadata=MetadataAttachment* Body=FuncBody
;

# ref: ParseFunctionHeader
#
#   ::= OptionalLinkage OptionalPreemptionSpecifier OptionalVisibility
#       OptionalCallingConv OptRetAttrs OptUnnamedAddr Type GlobalName
#       '(' ArgList ')' OptAddrSpace OptFuncAttrs OptSection OptPartition
#       OptionalAlign OptGC OptionalPrefix OptionalPrologue OptPersonalityFn

FuncHeader -> FuncHeader
	#: (Linkage | ExternLinkage)? Preemptionopt Visibilityopt DLLStorageClassopt CallingConvopt ReturnAttrs=ReturnAttribute* RetType=Type Name=GlobalIdent '(' Params ')' UnnamedAddropt AddrSpaceopt FuncAttrs=FuncAttributeAndAlign* Sectionopt Partitionopt Comdatopt Alignopt GCopt Prefixopt Prologueopt Personalityopt
	: (Linkage | ExternLinkage)? Preemptionopt Visibilityopt DLLStorageClassopt CallingConvopt ReturnAttrs=ReturnAttribute* RetType=Type Name=GlobalIdent '(' Params ')' UnnamedAddropt AddrSpaceopt FuncHdrFields=FuncHdrField*
;

# NOTE: FuncHdrField is a workaround to handle the LR-1 shift/reduce conflict
# between FuncAttribute and Align, both of which contain 'align'.

%interface FuncHdrField;

FuncHdrField -> FuncHdrField
	: FuncAttribute
	| Section
	| Partition
	| Comdat
	| Align
	| GC
	| Prefix
	| Prologue
	| Personality
;

# NOTE: Named GCNode instead of GC to avoid collisions with 'gc' token. Both
# define an identifier GC, the former in listener.go and the latter in
# token.go.
#
# Upstream issue: https://github.com/inspirer/textmapper/issues/18

GC -> GCNode
	: 'gc' Name=StringLit
;

Prefix -> Prefix
	: 'prefix' TypeConst
;

Prologue -> Prologue
	: 'prologue' TypeConst
;

Personality -> Personality
	: 'personality' TypeConst
;

# ref: ParseFunctionBody
#
#   ::= '{' BasicBlock+ UseListOrderDirective* '}'

FuncBody -> FuncBody
	: '{' Blocks=BasicBlock+ UseListOrders=UseListOrder* '}'
;

# ~~~ [ Attribute Group Definition ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#attribute-groups

# ref: ParseUnnamedAttrGrp
#
#   ::= 'attributes' AttrGrpID '=' '{' AttrValPair+ '}'

AttrGroupDef -> AttrGroupDef
	: 'attributes' ID=AttrGroupID '=' '{' FuncAttrs=FuncAttribute* '}'
;

# ~~~ [ Named Metadata Definition ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#named-metadata

# ref: ParseNamedMetadata
#
#   !foo = !{ !1, !2 }

NamedMetadataDef -> NamedMetadataDef
	: Name=MetadataName '=' '!' '{' MDNodes=(MetadataNode separator ',')* '}'
;

%interface MetadataNode;

MetadataNode -> MetadataNode
	: MetadataID
	# Parse DIExpressions inline as a special case. They are still MDNodes, so
	# they can still appear in named metadata. Remove this logic if they become
	# plain Metadata.
	| DIExpression
;

# ~~~ [ Metadata Definition ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#metadata-nodes-and-metadata-strings

# ref: ParseStandaloneMetadata
#
#   !42 = !{...}

MetadataDef -> MetadataDef
	: ID=MetadataID '=' Distinctopt MDNode=MDTuple
	| ID=MetadataID '=' Distinctopt MDNode=SpecializedMDNode
;

Distinct -> Distinct
	: 'distinct'
;

# ~~~ [ Use-list Order Directives ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#use-list-order-directives

# ref: ParseUseListOrder
#
#   ::= 'uselistorder' Type Value ',' UseListOrderIndexes
#  UseListOrderIndexes
#   ::= '{' uint32 (',' uint32)+ '}'

UseListOrder -> UseListOrder
	: 'uselistorder' Val=TypeValue ',' '{' Indices=(UintLit separator ',')+ '}'
;

# ref: ParseUseListOrderBB
#
#   ::= 'uselistorder_bb' @foo ',' %bar ',' UseListOrderIndexes

UseListOrderBB -> UseListOrderBB
	: 'uselistorder_bb' Func=GlobalIdent ',' Block=LocalIdent ',' '{' Indices=(UintLit separator ',')+ '}'
;

# === [ Types ] ================================================================

# ref: ParseType
#
#  TYPEKEYWORD("void",      Type::getVoidTy(Context));
#  TYPEKEYWORD("half",      Type::getHalfTy(Context));
#  TYPEKEYWORD("float",     Type::getFloatTy(Context));
#  TYPEKEYWORD("double",    Type::getDoubleTy(Context));
#  TYPEKEYWORD("x86_fp80",  Type::getX86_FP80Ty(Context));
#  TYPEKEYWORD("fp128",     Type::getFP128Ty(Context));
#  TYPEKEYWORD("ppc_fp128", Type::getPPC_FP128Ty(Context));
#  TYPEKEYWORD("label",     Type::getLabelTy(Context));
#  TYPEKEYWORD("metadata",  Type::getMetadataTy(Context));
#  TYPEKEYWORD("x86_mmx",   Type::getX86_MMXTy(Context));
#  TYPEKEYWORD("token",     Type::getTokenTy(Context));

%interface Type;

Type -> Type
	: VoidType
	| FuncType
	| FirstClassType
;

%interface FirstClassType;

FirstClassType -> FirstClassType
	: ConcreteType
	| MetadataType
;

%interface ConcreteType;

ConcreteType -> ConcreteType
	: IntType
	# Type ::= 'float' | 'void' (etc)
	| FloatType
	# Type ::= Type '*'
	# Type ::= Type 'addrspace' '(' uint32 ')' '*'
	| PointerType
	# Type ::= '<' ... '>'
	| VectorType
	| LabelType
	# Type ::= '[' ... ']'
	| ArrayType
	# Type ::= StructType
	| StructType
	# Type ::= %foo
	# Type ::= %4
	| NamedType
	| MMXType
	| TokenType
;

# --- [ Void Types ] -----------------------------------------------------------

VoidType -> VoidType
	: 'void'
;

# --- [ Function Types ] -------------------------------------------------------

# ref: ParseFunctionType
#
#  ::= Type ArgumentList OptionalAttrs

FuncType -> FuncType
	: RetType=Type '(' Params ')'
;

# --- [ Integer Types ] --------------------------------------------------------

IntType -> IntType
	: int_type_tok
;

# --- [ Floating-point Types ] -------------------------------------------------

FloatType -> FloatType
	: FloatKind
;

FloatKind -> FloatKind
	: 'half'
	| 'float'
	| 'double'
	| 'x86_fp80'
	| 'fp128'
	| 'ppc_fp128'
;

# --- [ MMX Types ] ------------------------------------------------------------

MMXType -> MMXType
	: 'x86_mmx'
;

# --- [ Pointer Types ] --------------------------------------------------------

PointerType -> PointerType
	: Elem=Type AddrSpaceopt '*'
;

# --- [ Vector Types ] ---------------------------------------------------------

# ref: ParseArrayVectorType
#
#     ::= '<' APSINTVAL 'x' Types '>'

VectorType -> VectorType
	: '<' Len=UintLit 'x' Elem=Type '>'
	| '<' 'vscale' 'x' Len=UintLit 'x' Elem=Type '>' -> ScalableVectorType
;

# --- [ Label Types ] ----------------------------------------------------------

LabelType -> LabelType
	: 'label'
;

# --- [ Token Types ] ----------------------------------------------------------

TokenType -> TokenType
	: 'token'
;

# --- [ Metadata Types ] -------------------------------------------------------

MetadataType -> MetadataType
	: 'metadata'
;

# --- [ Array Types ] ----------------------------------------------------------

# ref: ParseArrayVectorType
#
#     ::= '[' APSINTVAL 'x' Types ']'

ArrayType -> ArrayType
	: '[' Len=UintLit 'x' Elem=Type ']'
;

# --- [ Structure Types ] ------------------------------------------------------

# ref: ParseStructBody
#
#   StructType
#     ::= '{' '}'
#     ::= '{' Type (',' Type)* '}'
#     ::= '<' '{' '}' '>'
#     ::= '<' '{' Type (',' Type)* '}' '>'

StructType -> StructType
	: '{' Fields=(Type separator ',')+? '}'
	| '<' '{' Fields=(Type separator ',')+? '}' '>'   -> PackedStructType
;

OpaqueType -> OpaqueType
	: 'opaque'
;

# --- [ Named Types ] ----------------------------------------------------------

NamedType -> NamedType
	: Name=LocalIdent
;

# === [ Values ] ===============================================================

# ref: ParseValue

%interface Value;

Value -> Value
	: Constant
	# %42
	# %foo
	| LocalIdent
	# TODO: Move InlineAsm from Value to Callee and Invokee?
	# Inline assembler expressions may only be used as the callee operand of a
	# call or an invoke instruction.
	| InlineAsm
;

# --- [ Inline Assembler Expressions ] -----------------------------------------

# https://llvm.org/docs/LangRef.html#inline-assembler-expressions

# ref: ParseValID
#
#  ::= 'asm' SideEffect? AlignStack? IntelDialect? STRINGCONSTANT ','
#             STRINGCONSTANT

InlineAsm -> InlineAsm
	: 'asm' SideEffectopt AlignStackTokopt IntelDialectopt Asm=StringLit ',' Constraints=StringLit
;

SideEffect -> SideEffect
	: 'sideeffect'
;

AlignStackTok -> AlignStackTok
	: 'alignstack'
;

IntelDialect -> IntelDialect
	: 'inteldialect'
;

# === [ Constants ] ============================================================

# https://llvm.org/docs/LangRef.html#constants

# ref: ParseValID

%interface Constant;

Constant -> Constant
	: BoolConst
	| IntConst
	| FloatConst
	| NullConst
	| NoneConst
	| StructConst
	| ArrayConst
	| VectorConst
	| ZeroInitializerConst
	# @42
	# @foo
	| GlobalIdent
	| UndefConst
	| BlockAddressConst
	| ConstantExpr
;

# --- [ Boolean Constants ] ----------------------------------------------------

# https://llvm.org/docs/LangRef.html#simple-constants

# ref: ParseValID

BoolConst -> BoolConst
	: BoolLit
;

# --- [ Integer Constants ] ----------------------------------------------------

# https://llvm.org/docs/LangRef.html#simple-constants

# ref: ParseValID

IntConst -> IntConst
	: IntLit
;

# --- [ Floating-point Constants ] ---------------------------------------------

# https://llvm.org/docs/LangRef.html#simple-constants

# ref: ParseValID

FloatConst -> FloatConst
	: FloatLit
;

# --- [ Null Pointer Constants ] -----------------------------------------------

# https://llvm.org/docs/LangRef.html#simple-constants

# ref: ParseValID

NullConst -> NullConst
	: NullLit
;

# --- [ Token Constants ] ------------------------------------------------------

# https://llvm.org/docs/LangRef.html#simple-constants

# ref: ParseValID

NoneConst -> NoneConst
	: 'none'
;

# --- [ Structure Constants ] --------------------------------------------------

# https://llvm.org/docs/LangRef.html#complex-constants

# ref: ParseValID
#
#  ::= '{' ConstVector '}'
#  ::= '<' '{' ConstVector '}' '>' --> Packed Struct.

StructConst -> StructConst
	: '{' Fields=(TypeConst separator ',')+? '}'
	| '<' '{' Fields=(TypeConst separator ',')+? '}' '>'
;

# --- [ Array Constants ] ------------------------------------------------------

# https://llvm.org/docs/LangRef.html#complex-constants

# ref: ParseValID
#
#  c "foo"

ArrayConst -> ArrayConst
	: '[' Elems=(TypeConst separator ',')* ']'
	| 'c' Val=StringLit                          -> CharArrayConst
;

# --- [ Vector Constants ] -----------------------------------------------------

# https://llvm.org/docs/LangRef.html#complex-constants

# ref: ParseValID
#
#  ::= '<' ConstVector '>'         --> Vector.

VectorConst -> VectorConst
	: '<' Elems=(TypeConst separator ',')* '>'
;

# --- [ Zero Initialization Constants ] ----------------------------------------

# https://llvm.org/docs/LangRef.html#complex-constants

# ref: ParseValID

ZeroInitializerConst -> ZeroInitializerConst
	: 'zeroinitializer'
;

# --- [ Undefined Values ] -----------------------------------------------------

# https://llvm.org/docs/LangRef.html#undefined-values

# ref: ParseValID

UndefConst -> UndefConst
	: 'undef'
;

# --- [ Addresses of Basic Blocks ] --------------------------------------------

# https://llvm.org/docs/LangRef.html#addresses-of-basic-blocks

# ref: ParseValID
#
#  ::= 'blockaddress' '(' @foo ',' %bar ')'

BlockAddressConst -> BlockAddressConst
	: 'blockaddress' '(' Func=GlobalIdent ',' Block=LocalIdent ')'
;

# === [ Constant expressions ] =================================================

# https://llvm.org/docs/LangRef.html#constant-expressions

# ref: ParseValID

%interface ConstantExpr;

ConstantExpr -> ConstantExpr
	# Unary expressions
	: FNegExpr
	# Binary expressions
	| AddExpr
	| FAddExpr
	| SubExpr
	| FSubExpr
	| MulExpr
	| FMulExpr
	| UDivExpr
	| SDivExpr
	| FDivExpr
	| URemExpr
	| SRemExpr
	| FRemExpr
	# Bitwise expressions
	| ShlExpr
	| LShrExpr
	| AShrExpr
	| AndExpr
	| OrExpr
	| XorExpr
	# Vector expressions
	| ExtractElementExpr
	| InsertElementExpr
	| ShuffleVectorExpr
	# Aggregate expressions
	| ExtractValueExpr
	| InsertValueExpr
	# Memory expressions
	| GetElementPtrExpr
	# Conversion expressions
	| TruncExpr
	| ZExtExpr
	| SExtExpr
	| FPTruncExpr
	| FPExtExpr
	| FPToUIExpr
	| FPToSIExpr
	| UIToFPExpr
	| SIToFPExpr
	| PtrToIntExpr
	| IntToPtrExpr
	| BitCastExpr
	| AddrSpaceCastExpr
	# Other expressions
	| ICmpExpr
	| FCmpExpr
	| SelectExpr
;

# --- [ Unary expressions ] ----------------------------------------------------

# https://llvm.org/docs/LangRef.html#constant-expressions

# ~~~ [ fneg ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

FNegExpr -> FNegExpr
	: 'fneg' '(' X=TypeConst ')'
;

# --- [ Binary expressions ] --------------------------------------------------

# https://llvm.org/docs/LangRef.html#constant-expressions

# ~~~ [ add ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

AddExpr -> AddExpr
	: 'add' OverflowFlags=OverflowFlag* '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ fadd ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

FAddExpr -> FAddExpr
	: 'fadd' '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ sub ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

SubExpr -> SubExpr
	: 'sub' OverflowFlags=OverflowFlag* '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ fsub ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

FSubExpr -> FSubExpr
	: 'fsub' '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ mul ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

MulExpr -> MulExpr
	: 'mul' OverflowFlags=OverflowFlag* '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ fmul ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

FMulExpr -> FMulExpr
	: 'fmul' '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ udiv ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

UDivExpr -> UDivExpr
	: 'udiv' Exactopt '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ sdiv ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

SDivExpr -> SDivExpr
	: 'sdiv' Exactopt '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ fdiv ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

FDivExpr -> FDivExpr
	: 'fdiv' '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ urem ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

URemExpr -> URemExpr
	: 'urem' '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ srem ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

SRemExpr -> SRemExpr
	: 'srem' '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ frem ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

FRemExpr -> FRemExpr
	: 'frem' '(' X=TypeConst ',' Y=TypeConst ')'
;

# --- [ Bitwise expressions ] --------------------------------------------------

# https://llvm.org/docs/LangRef.html#constant-expressions

# ~~~ [ shl ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

ShlExpr -> ShlExpr
	: 'shl' OverflowFlags=OverflowFlag* '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ lshr ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

LShrExpr -> LShrExpr
	: 'lshr' Exactopt '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ ashr ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

AShrExpr -> AShrExpr
	: 'ashr' Exactopt '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ and ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

AndExpr -> AndExpr
	: 'and' '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ or ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

OrExpr -> OrExpr
	: 'or' '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ xor ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

XorExpr -> XorExpr
	: 'xor' '(' X=TypeConst ',' Y=TypeConst ')'
;

# --- [ Vector expressions ] ---------------------------------------------------

# https://llvm.org/docs/LangRef.html#constant-expressions

# ~~~ [ extractelement ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

ExtractElementExpr -> ExtractElementExpr
	: 'extractelement' '(' X=TypeConst ',' Index=TypeConst ')'
;

# ~~~ [ insertelement ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

InsertElementExpr -> InsertElementExpr
	: 'insertelement' '(' X=TypeConst ',' Elem=TypeConst ',' Index=TypeConst ')'
;

# ~~~ [ shufflevector ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

ShuffleVectorExpr -> ShuffleVectorExpr
	: 'shufflevector' '(' X=TypeConst ',' Y=TypeConst ',' Mask=TypeConst ')'
;

# --- [ Aggregate expressions ] ------------------------------------------------

# https://llvm.org/docs/LangRef.html#constant-expressions

# ~~~ [ extractvalue ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

ExtractValueExpr -> ExtractValueExpr
	: 'extractvalue' '(' X=TypeConst Indices=(',' UintLit)* ')'
;

# ~~~ [ insertvalue ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

InsertValueExpr -> InsertValueExpr
	: 'insertvalue' '(' X=TypeConst ',' Elem=TypeConst Indices=(',' UintLit)* ')'
;

# --- [ Memory expressions ] ---------------------------------------------------

# https://llvm.org/docs/LangRef.html#constant-expressions

# ~~~ [ getelementptr ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

GetElementPtrExpr -> GetElementPtrExpr
	: 'getelementptr' InBoundsopt '(' ElemType=Type ',' Src=TypeConst Indices=(',' GEPIndex)* ')'
;

# ref: ParseGlobalValueVector
#
#   ::= empty
#   ::= [inrange] TypeAndValue (',' [inrange] TypeAndValue)*

GEPIndex -> GEPIndex
	: InRangeopt Index=TypeConst
;

InRange -> InRange
	: 'inrange'
;

# --- [ Conversion expressions ] -----------------------------------------------

# https://llvm.org/docs/LangRef.html#constant-expressions

# ~~~ [ trunc ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

TruncExpr -> TruncExpr
	: 'trunc' '(' From=TypeConst 'to' To=Type ')'
;

# ~~~ [ zext ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

ZExtExpr -> ZExtExpr
	: 'zext' '(' From=TypeConst 'to' To=Type ')'
;

# ~~~ [ sext ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

SExtExpr -> SExtExpr
	: 'sext' '(' From=TypeConst 'to' To=Type ')'
;

# ~~~ [ fptrunc ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

FPTruncExpr -> FPTruncExpr
	: 'fptrunc' '(' From=TypeConst 'to' To=Type ')'
;

# ~~~ [ fpext ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

FPExtExpr -> FPExtExpr
	: 'fpext' '(' From=TypeConst 'to' To=Type ')'
;

# ~~~ [ fptoui ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

FPToUIExpr -> FPToUIExpr
	: 'fptoui' '(' From=TypeConst 'to' To=Type ')'
;

# ~~~ [ fptosi ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

FPToSIExpr -> FPToSIExpr
	: 'fptosi' '(' From=TypeConst 'to' To=Type ')'
;

# ~~~ [ uitofp ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

UIToFPExpr -> UIToFPExpr
	: 'uitofp' '(' From=TypeConst 'to' To=Type ')'
;

# ~~~ [ sitofp ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

SIToFPExpr -> SIToFPExpr
	: 'sitofp' '(' From=TypeConst 'to' To=Type ')'
;

# ~~~ [ ptrtoint ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

PtrToIntExpr -> PtrToIntExpr
	: 'ptrtoint' '(' From=TypeConst 'to' To=Type ')'
;

# ~~~ [ inttoptr ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

IntToPtrExpr -> IntToPtrExpr
	: 'inttoptr' '(' From=TypeConst 'to' To=Type ')'
;

# ~~~ [ bitcast ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

BitCastExpr -> BitCastExpr
	: 'bitcast' '(' From=TypeConst 'to' To=Type ')'
;

# ~~~ [ addrspacecast ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

AddrSpaceCastExpr -> AddrSpaceCastExpr
	: 'addrspacecast' '(' From=TypeConst 'to' To=Type ')'
;

# --- [ Other expressions ] ----------------------------------------------------

# https://llvm.org/docs/LangRef.html#constant-expressions

# ~~~ [ icmp ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

ICmpExpr -> ICmpExpr
	: 'icmp' Pred=IPred '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ fcmp ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

FCmpExpr -> FCmpExpr
	: 'fcmp' Pred=FPred '(' X=TypeConst ',' Y=TypeConst ')'
;

# ~~~ [ select ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseValID

SelectExpr -> SelectExpr
	: 'select' '(' Cond=TypeConst ',' X=TypeConst ',' Y=TypeConst ')'
;

# === [ Basic Blocks ] =========================================================

# ref: ParseBasicBlock
#
#   ::= (LabelStr|LabelID)? Instruction*

BasicBlock -> BasicBlock
	: Name=LabelIdentopt Insts=Instruction* Term=Terminator
;

# === [ Instructions ] =========================================================

# https://llvm.org/docs/LangRef.html#instruction-reference

# ref: ParseInstruction

%interface Instruction;

Instruction -> Instruction
	# Instructions producing values.
	: LocalDefInst
	| ValueInstruction
	# Instructions not producing values.
	| StoreInst
	| FenceInst
;

LocalDefInst -> LocalDefInst
	: Name=LocalIdent '=' Inst=ValueInstruction
;

%interface ValueInstruction;

# List of value instructions is sorted in the same order as the LLVM LangRef.
#
# ref: https://llvm.org/docs/LangRef.html#instruction-reference
ValueInstruction -> ValueInstruction
	# Unary instructions
	: FNegInst
	# Binary instructions
	| AddInst
	| FAddInst
	| SubInst
	| FSubInst
	| MulInst
	| FMulInst
	| UDivInst
	| SDivInst
	| FDivInst
	| URemInst
	| SRemInst
	| FRemInst
	# Bitwise instructions
	| ShlInst
	| LShrInst
	| AShrInst
	| AndInst
	| OrInst
	| XorInst
	# Vector instructions
	| ExtractElementInst
	| InsertElementInst
	| ShuffleVectorInst
	# Aggregate instructions
	| ExtractValueInst
	| InsertValueInst
	# Memory instructions
	| AllocaInst
	| LoadInst
	| CmpXchgInst
	| AtomicRMWInst
	| GetElementPtrInst
	# Conversion instructions
	| TruncInst
	| ZExtInst
	| SExtInst
	| FPTruncInst
	| FPExtInst
	| FPToUIInst
	| FPToSIInst
	| UIToFPInst
	| SIToFPInst
	| PtrToIntInst
	| IntToPtrInst
	| BitCastInst
	| AddrSpaceCastInst
	# Other instructions
	| ICmpInst
	| FCmpInst
	| PhiInst
	| SelectInst
	| FreezeInst
	| CallInst
	| VAArgInst
	| LandingPadInst
	| CatchPadInst
	| CleanupPadInst
;

# --- [ Unary instructions ] ---------------------------------------------------

# ~~~ [ fneg ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#fneg-instruction

# ref: ParseUnaryOp
#
#  ::= UnaryOp TypeAndValue

FNegInst -> FNegInst
	: 'fneg' FastMathFlags=FastMathFlag* X=TypeValue Metadata=(',' MetadataAttachment)+?
;

# --- [ Binary instructions ] --------------------------------------------------

# ~~~ [ add ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#add-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

# ref: ParseInstructionMetadata
#
#   ::= !dbg !42 (',' !dbg !57)*

AddInst -> AddInst
	: 'add' OverflowFlags=OverflowFlag* X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ fadd ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#fadd-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

FAddInst -> FAddInst
	: 'fadd' FastMathFlags=FastMathFlag* X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ sub ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#sub-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

SubInst -> SubInst
	: 'sub' OverflowFlags=OverflowFlag* X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ fsub ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#fsub-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

FSubInst -> FSubInst
	: 'fsub' FastMathFlags=FastMathFlag* X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ mul ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#mul-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

MulInst -> MulInst
	: 'mul' OverflowFlags=OverflowFlag* X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ fmul ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#fmul-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

FMulInst -> FMulInst
	: 'fmul' FastMathFlags=FastMathFlag* X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ udiv ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#udiv-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

UDivInst -> UDivInst
	: 'udiv' Exactopt X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ sdiv ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#sdiv-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

SDivInst -> SDivInst
	: 'sdiv' Exactopt X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ fdiv ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#fdiv-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

FDivInst -> FDivInst
	: 'fdiv' FastMathFlags=FastMathFlag* X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ urem ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#urem-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

URemInst -> URemInst
	: 'urem' X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ srem ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#srem-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

SRemInst -> SRemInst
	: 'srem' X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ frem ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#frem-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

FRemInst -> FRemInst
	: 'frem' FastMathFlags=FastMathFlag* X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# --- [ Bitwise instructions ] -------------------------------------------------

# ~~~ [ shl ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#shl-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

ShlInst -> ShlInst
	: 'shl' OverflowFlags=OverflowFlag* X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ lshr ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#lshr-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

LShrInst -> LShrInst
	: 'lshr' Exactopt X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ ashr ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#ashr-instruction

# ref: ParseArithmetic
#
#  ::= ArithmeticOps TypeAndValue ',' Value

AShrInst -> AShrInst
	: 'ashr' Exactopt X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ and ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#and-instruction

# ref: ParseLogical
#
#  ::= ArithmeticOps TypeAndValue ',' Value {

AndInst -> AndInst
	: 'and' X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ or ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#or-instruction

# ref: ParseLogical
#
#  ::= ArithmeticOps TypeAndValue ',' Value {

OrInst -> OrInst
	: 'or' X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ xor ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#xor-instruction

# ref: ParseLogical
#
#  ::= ArithmeticOps TypeAndValue ',' Value {

XorInst -> XorInst
	: 'xor' X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# --- [ Vector instructions ] --------------------------------------------------

# ~~~ [ extractelement ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#extractelement-instruction

# ref: ParseExtractElement
#
#   ::= 'extractelement' TypeAndValue ',' TypeAndValue

ExtractElementInst -> ExtractElementInst
	: 'extractelement' X=TypeValue ',' Index=TypeValue Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ insertelement ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#insertelement-instruction

# ref: ParseInsertElement
#
#   ::= 'insertelement' TypeAndValue ',' TypeAndValue ',' TypeAndValue

InsertElementInst -> InsertElementInst
	: 'insertelement' X=TypeValue ',' Elem=TypeValue ',' Index=TypeValue Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ shufflevector ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#shufflevector-instruction

# ref: ParseShuffleVector
#
#   ::= 'shufflevector' TypeAndValue ',' TypeAndValue ',' TypeAndValue

ShuffleVectorInst -> ShuffleVectorInst
	: 'shufflevector' X=TypeValue ',' Y=TypeValue ',' Mask=TypeValue Metadata=(',' MetadataAttachment)+?
;

# --- [ Aggregate instructions ] -----------------------------------------------

# ~~~ [ extractvalue ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#extractvalue-instruction

# ref: ParseExtractValue
#
#   ::= 'extractvalue' TypeAndValue (',' uint32)+

ExtractValueInst -> ExtractValueInst
   : 'extractvalue' X=TypeValue Indices=(',' UintLit)+ Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ insertvalue ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#insertvalue-instruction

# ref: ParseInsertValue
#
#   ::= 'insertvalue' TypeAndValue ',' TypeAndValue (',' uint32)+

InsertValueInst -> InsertValueInst
   : 'insertvalue' X=TypeValue ',' Elem=TypeValue Indices=(',' UintLit)+ Metadata=(',' MetadataAttachment)+?
;

# --- [ Memory instructions ] --------------------------------------------------

# ~~~ [ alloca ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#alloca-instruction

# ref: ParseAlloc
#
#   ::= 'alloca' 'inalloca'? 'swifterror'? Type (',' TypeAndValue)?
#       (',' 'align' i32)? (',', 'addrspace(n))?

AllocaInst -> AllocaInst
	: 'alloca' InAllocaopt SwiftErroropt ElemType=Type NElems=(',' TypeValue)? (',' Align)? (',' AddrSpace)? Metadata=(',' MetadataAttachment)+?
;

InAlloca -> InAlloca
	: 'inalloca'
;

SwiftError -> SwiftError
	: 'swifterror'
;

# ~~~ [ load ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#load-instruction

# ref: ParseLoad
#
#   ::= 'load' 'volatile'? TypeAndValue (',' 'align' i32)?
#   ::= 'load' 'atomic' 'volatile'? TypeAndValue
#       'singlethread'? AtomicOrdering (',' 'align' i32)?

LoadInst -> LoadInst
	# Load.
	: 'load' Volatileopt ElemType=Type ',' Src=TypeValue (',' Align)? Metadata=(',' MetadataAttachment)+?
	# Atomic load.
	| 'load' Atomic Volatileopt ElemType=Type ',' Src=TypeValue SyncScopeopt Ordering=AtomicOrdering (',' Align)? Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ store ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#store-instruction

# ref: ParseStore
#
#   ::= 'store' 'volatile'? TypeAndValue ',' TypeAndValue (',' 'align' i32)?
#   ::= 'store' 'atomic' 'volatile'? TypeAndValue ',' TypeAndValue
#       'singlethread'? AtomicOrdering (',' 'align' i32)?

StoreInst -> StoreInst
	# Store.
	: 'store' Volatileopt Src=TypeValue ',' Dst=TypeValue (',' Align)? Metadata=(',' MetadataAttachment)+?
	# Atomic store.
	| 'store' Atomic Volatileopt Src=TypeValue ',' Dst=TypeValue SyncScopeopt Ordering=AtomicOrdering (',' Align)? Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ fence ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#fence-instruction

# ref: ParseFence
#
#   ::= 'fence' 'singlethread'? AtomicOrdering

FenceInst -> FenceInst
	: 'fence' SyncScopeopt Ordering=AtomicOrdering Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ cmpxchg ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#cmpxchg-instruction

# ref: ParseCmpXchg
#
#   ::= 'cmpxchg' 'weak'? 'volatile'? TypeAndValue ',' TypeAndValue ','
#       TypeAndValue 'singlethread'? AtomicOrdering AtomicOrdering

CmpXchgInst -> CmpXchgInst
	: 'cmpxchg' Weakopt Volatileopt Ptr=TypeValue ',' Cmp=TypeValue ',' New=TypeValue SyncScopeopt SuccessOrdering=AtomicOrdering FailureOrdering=AtomicOrdering Metadata=(',' MetadataAttachment)+?
;

Weak -> Weak
	: 'weak'
;

# ~~~ [ atomicrmw ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#atomicrmw-instruction

# ref: ParseAtomicRMW
#
#   ::= 'atomicrmw' 'volatile'? BinOp TypeAndValue ',' TypeAndValue
#       'singlethread'? AtomicOrdering

AtomicRMWInst -> AtomicRMWInst
	: 'atomicrmw' Volatileopt Op=AtomicOp Dst=TypeValue ',' X=TypeValue SyncScopeopt Ordering=AtomicOrdering Metadata=(',' MetadataAttachment)+?
;

AtomicOp -> AtomicOp
	: 'add'
	| 'and'
	| 'fadd'
	| 'fsub'
	| 'max'
	| 'min'
	| 'nand'
	| 'or'
	| 'sub'
	| 'umax'
	| 'umin'
	| 'xchg'
	| 'xor'
;

# ~~~ [ getelementptr ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#getelementptr-instruction

# ref: ParseGetElementPtr
#
#   ::= 'getelementptr' 'inbounds'? TypeAndValue (',' TypeAndValue)*

GetElementPtrInst -> GetElementPtrInst
	: 'getelementptr' InBoundsopt ElemType=Type ',' Src=TypeValue Indices=(',' TypeValue)* Metadata=(',' MetadataAttachment)+?
;

# --- [ Conversion instructions ] ----------------------------------------------

# ~~~ [ trunc ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#trunc-instruction

# ref: ParseCast
#
#   ::= CastOpc TypeAndValue 'to' Type

TruncInst -> TruncInst
	: 'trunc' From=TypeValue 'to' To=Type Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ zext ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#zext-instruction

# ref: ParseCast
#
#   ::= CastOpc TypeAndValue 'to' Type

ZExtInst -> ZExtInst
	: 'zext' From=TypeValue 'to' To=Type Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ sext ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#sext-instruction

# ref: ParseCast
#
#   ::= CastOpc TypeAndValue 'to' Type

SExtInst -> SExtInst
	: 'sext' From=TypeValue 'to' To=Type Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ fptrunc ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#fptrunc-instruction

# ref: ParseCast
#
#   ::= CastOpc TypeAndValue 'to' Type

FPTruncInst -> FPTruncInst
	: 'fptrunc' From=TypeValue 'to' To=Type Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ fpext ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#fpext-instruction

# ref: ParseCast
#
#   ::= CastOpc TypeAndValue 'to' Type

FPExtInst -> FPExtInst
	: 'fpext' From=TypeValue 'to' To=Type Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ fptoui ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#fptoui-instruction

# ref: ParseCast
#
#   ::= CastOpc TypeAndValue 'to' Type

FPToUIInst -> FPToUIInst
	: 'fptoui' From=TypeValue 'to' To=Type Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ fptosi ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#fptosi-instruction

# ref: ParseCast
#
#   ::= CastOpc TypeAndValue 'to' Type

FPToSIInst -> FPToSIInst
	: 'fptosi' From=TypeValue 'to' To=Type Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ uitofp ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#uitofp-instruction

# ref: ParseCast
#
#   ::= CastOpc TypeAndValue 'to' Type

UIToFPInst -> UIToFPInst
	: 'uitofp' From=TypeValue 'to' To=Type Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ sitofp ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#sitofp-instruction

# ref: ParseCast
#
#   ::= CastOpc TypeAndValue 'to' Type

SIToFPInst -> SIToFPInst
	: 'sitofp' From=TypeValue 'to' To=Type Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ ptrtoint ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#ptrtoint-instruction

# ref: ParseCast
#
#   ::= CastOpc TypeAndValue 'to' Type

PtrToIntInst -> PtrToIntInst
	: 'ptrtoint' From=TypeValue 'to' To=Type Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ inttoptr ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#inttoptr-instruction

# ref: ParseCast
#
#   ::= CastOpc TypeAndValue 'to' Type

IntToPtrInst -> IntToPtrInst
	: 'inttoptr' From=TypeValue 'to' To=Type Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ bitcast ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#bitcast-instruction

# ref: ParseCast
#
#   ::= CastOpc TypeAndValue 'to' Type

BitCastInst -> BitCastInst
	: 'bitcast' From=TypeValue 'to' To=Type Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ addrspacecast ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#addrspacecast-instruction

# ref: ParseCast
#
#   ::= CastOpc TypeAndValue 'to' Type

AddrSpaceCastInst -> AddrSpaceCastInst
	: 'addrspacecast' From=TypeValue 'to' To=Type Metadata=(',' MetadataAttachment)+?
;

# --- [ Other instructions ] ---------------------------------------------------

# ~~~ [ icmp ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#icmp-instruction

# ref: ParseCompare
#
#  ::= 'icmp' IPredicates TypeAndValue ',' Value

ICmpInst -> ICmpInst
	: 'icmp' Pred=IPred X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ fcmp ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#fcmp-instruction

# ref: ParseCompare
#
#  ::= 'fcmp' FPredicates TypeAndValue ',' Value

FCmpInst -> FCmpInst
	: 'fcmp' FastMathFlags=FastMathFlag* Pred=FPred X=TypeValue ',' Y=Value Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ phi ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#phi-instruction

# ref: ParsePHI
#
#   ::= 'phi' FastMathFlag* Type '[' Value ',' Value ']' (',' '[' Value ',' Value ']')*

PhiInst -> PhiInst
	: 'phi' FastMathFlags=FastMathFlag* Typ=Type Incs=(Inc separator ',')+ Metadata=(',' MetadataAttachment)+?
;

Inc -> Inc
	: '[' X=Value ',' Pred=LocalIdent ']'
;

# ~~~ [ select ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#select-instruction

# ref: ParseSelect
#
#   ::= 'select' TypeAndValue ',' TypeAndValue ',' TypeAndValue

SelectInst -> SelectInst
	: 'select' FastMathFlags=FastMathFlag* Cond=TypeValue ',' ValueTrue=TypeValue ',' ValueFalse=TypeValue Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ freeze ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#freeze-instruction

# ref: ParseFreeze
#
#   ::= 'freeze' Type Value

FreezeInst -> FreezeInst
    : 'freeze' X=TypeValue
;

# ~~~ [ call ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#call-instruction

# ref: ParseCall
#
#   ::= 'call' OptionalFastMathFlags OptionalCallingConv
#           OptionalAttrs Type Value ParameterList OptionalAttrs
#   ::= 'tail' 'call' OptionalFastMathFlags OptionalCallingConv
#           OptionalAttrs Type Value ParameterList OptionalAttrs
#   ::= 'musttail' 'call' OptionalFastMathFlags OptionalCallingConv
#           OptionalAttrs Type Value ParameterList OptionalAttrs
#   ::= 'notail' 'call'  OptionalFastMathFlags OptionalCallingConv
#           OptionalAttrs Type Value ParameterList OptionalAttrs

# ref: ParseOptionalOperandBundles
#
#    ::= empty
#    ::= '[' OperandBundle [, OperandBundle ]* ']'
#
#  OperandBundle
#    ::= bundle-tag '(' ')'
#    ::= bundle-tag '(' Type Value [, Type Value ]* ')'
#
#  bundle-tag ::= String Constant

# TODO: add align as valid function attribute to CallInst.

CallInst -> CallInst
	: Tailopt 'call' FastMathFlags=FastMathFlag* CallingConvopt ReturnAttrs=ReturnAttribute* AddrSpaceopt Typ=Type Callee=Value '(' Args ')' FuncAttrs=FuncAttribute* OperandBundles=('[' (OperandBundle separator ',')+ ']')? Metadata=(',' MetadataAttachment)+?
;

Tail -> Tail
	: 'musttail'
	| 'notail'
	| 'tail'
;

# ~~~ [ va_arg ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#va_arg-instruction

# ref: ParseVA_Arg
#
#   ::= 'va_arg' TypeAndValue ',' Type

VAArgInst -> VAArgInst
	: 'va_arg' ArgList=TypeValue ',' ArgType=Type Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ landingpad ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#landingpad-instruction

# ref: ParseLandingPad
#
#   ::= 'landingpad' Type 'personality' TypeAndValue 'cleanup'? Clause+
#  Clause
#   ::= 'catch' TypeAndValue
#   ::= 'filter'
#   ::= 'filter' TypeAndValue ( ',' TypeAndValue )*

LandingPadInst -> LandingPadInst
	: 'landingpad' ResultType=Type Cleanupopt Clauses=Clause* Metadata=(',' MetadataAttachment)+?
;

Cleanup -> Cleanup
	: 'cleanup'
;

Clause -> Clause
	: ClauseType X=TypeValue
;

ClauseType -> ClauseType
	: 'catch'
	| 'filter'
;

# ~~~ [ catchpad ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseCatchPad
#
#   ::= 'catchpad' ParamList 'to' TypeAndValue 'unwind' TypeAndValue

CatchPadInst -> CatchPadInst
	: 'catchpad' 'within' CatchSwitch=LocalIdent '[' Args=(ExceptionArg separator ',')* ']' Metadata=(',' MetadataAttachment)+?
;

# ~~~ [ cleanuppad ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ref: ParseCleanupPad
#
#   ::= 'cleanuppad' within Parent ParamList

CleanupPadInst -> CleanupPadInst
	: 'cleanuppad' 'within' ParentPad=ExceptionPad '[' Args=(ExceptionArg separator ',')* ']' Metadata=(',' MetadataAttachment)+?
;

# === [ Terminators ] ==========================================================

# https://llvm.org/docs/LangRef.html#terminator-instructions

# ref: ParseInstruction

%interface Terminator;

Terminator -> Terminator
	# Terminators producing values.
	: LocalDefTerm
	| ValueTerminator
	# Terminators not producing values.
	| RetTerm
	| BrTerm
	| CondBrTerm
	| SwitchTerm
	| IndirectBrTerm
	| ResumeTerm
	| CatchRetTerm
	| CleanupRetTerm
	| UnreachableTerm
;

LocalDefTerm -> LocalDefTerm
	: Name=LocalIdent '=' Term=ValueTerminator
;

%interface ValueTerminator;

ValueTerminator -> ValueTerminator
	: InvokeTerm
	| CallBrTerm
	| CatchSwitchTerm
;

# --- [ ret ] ------------------------------------------------------------------

# https://llvm.org/docs/LangRef.html#ret-instruction

# ref: ParseRet
#
#   ::= 'ret' void (',' !dbg, !1)*
#   ::= 'ret' TypeAndValue (',' !dbg, !1)*

RetTerm -> RetTerm
	# Void return.
	: 'ret' XTyp=VoidType Metadata=(',' MetadataAttachment)+?
	# Value return.
	| 'ret' XTyp=ConcreteType X=Value Metadata=(',' MetadataAttachment)+?
;

# --- [ br ] -------------------------------------------------------------------

# https://llvm.org/docs/LangRef.html#br-instruction

# ref: ParseBr
#
#   ::= 'br' TypeAndValue
#   ::= 'br' TypeAndValue ',' TypeAndValue ',' TypeAndValue

# Unconditional branch.
BrTerm -> BrTerm
	: 'br' Target=Label Metadata=(',' MetadataAttachment)+?
;

# TODO: replace `IntType Value` with TypeValue when the parser generator
# is capable of handling the shift/reduce conflict. When TypeValue is used, the
# conflict happens as 'br' 'label' may be the start of either BrTerm or
# CondBrTerm.

# Conditional branch.
CondBrTerm -> CondBrTerm
	: 'br' CondTyp=IntType Cond=Value ',' TargetTrue=Label ',' TargetFalse=Label Metadata=(',' MetadataAttachment)+?
;

# --- [ switch ] ---------------------------------------------------------------

# https://llvm.org/docs/LangRef.html#switch-instruction

# ref: ParseSwitch
#
#    ::= 'switch' TypeAndValue ',' TypeAndValue '[' JumpTable ']'
#  JumpTable
#    ::= (TypeAndValue ',' TypeAndValue)*

SwitchTerm -> SwitchTerm
	: 'switch' X=TypeValue ',' Default=Label '[' Cases=Case* ']' Metadata=(',' MetadataAttachment)+?
;

Case -> Case
	: X=TypeConst ',' Target=Label
;

# --- [ indirectbr ] -----------------------------------------------------------

# https://llvm.org/docs/LangRef.html#indirectbr-instruction

# ref: ParseIndirectBr
#
#    ::= 'indirectbr' TypeAndValue ',' '[' LabelList ']'

IndirectBrTerm -> IndirectBrTerm
	: 'indirectbr' Addr=TypeValue ',' '[' ValidTargets=(Label separator ',')* ']' Metadata=(',' MetadataAttachment)+?
;

# --- [ invoke ] ---------------------------------------------------------------

# https://llvm.org/docs/LangRef.html#invoke-instruction

# ref: ParseInvoke
#
#   ::= 'invoke' OptionalCallingConv OptionalAttrs Type Value ParamList
#       OptionalAttrs 'to' TypeAndValue 'unwind' TypeAndValue

# TODO: add align as valid function attribute to InvokeTerm.

InvokeTerm -> InvokeTerm
	: 'invoke' CallingConvopt ReturnAttrs=ReturnAttribute* AddrSpaceopt Typ=Type Invokee=Value '(' Args ')' FuncAttrs=FuncAttribute* OperandBundles=('[' (OperandBundle separator ',')+ ']')? 'to' NormalRetTarget=Label 'unwind' ExceptionRetTarget=Label Metadata=(',' MetadataAttachment)+?
;

# --- [ callbr ] ---------------------------------------------------------------

# https://llvm.org/docs/LangRef.html#callbr-instruction

# ref: ParseCallBr
#
#   ::= 'callbr' OptionalCallingConv OptionalAttrs Type Value ParamList
#       OptionalAttrs OptionalOperandBundles 'to' TypeAndValue
#       '[' LabelList ']'

CallBrTerm -> CallBrTerm
	: 'callbr' CallingConvopt ReturnAttrs=ReturnAttribute* AddrSpaceopt Typ=Type Callee=Value '(' Args ')' FuncAttrs=FuncAttribute* OperandBundles=('[' (OperandBundle separator ',')+ ']')? 'to' NormalRetTarget=Label '[' OtherRetTargets=(Label separator ',')* ']' Metadata=(',' MetadataAttachment)+?
;

# --- [ resume ] ---------------------------------------------------------------

# https://llvm.org/docs/LangRef.html#resume-instruction

# ref: ParseResume
#
#   ::= 'resume' TypeAndValue

ResumeTerm -> ResumeTerm
	: 'resume' X=TypeValue Metadata=(',' MetadataAttachment)+?
;

# --- [ catchswitch ] ----------------------------------------------------------

# https://llvm.org/docs/LangRef.html#catchswitch-instruction

# ref: ParseCatchSwitch
#
#   ::= 'catchswitch' within Parent

CatchSwitchTerm -> CatchSwitchTerm
	: 'catchswitch' 'within' ParentPad=ExceptionPad '[' Handlers=Handlers ']' 'unwind' DefaultUnwindTarget=UnwindTarget Metadata=(',' MetadataAttachment)+?
;

# Use distinct production rule for Handlers. This is to avoid the Textmapper
# error: `'Handlers' cannot be a list, since it precedes UnwindTarget`, as
# caused by Handlers being a list of labels (i.e. `[]Label`) followed by a
# label as part of the UnwindTarget interface.
#
# Upstream issue https://github.com/inspirer/textmapper/issues/25
#
# When declarative inlining is supported, we may want to inline Handlers.

Handlers -> Handlers
	: Labels=(Label separator ',')+
;

# --- [ catchret ] -------------------------------------------------------------

# https://llvm.org/docs/LangRef.html#catchret-instruction

# ref: ParseCatchRet
#
#   ::= 'catchret' from Parent Value 'to' TypeAndValue

CatchRetTerm -> CatchRetTerm
	: 'catchret' 'from' CatchPad=Value 'to' Target=Label Metadata=(',' MetadataAttachment)+?
;

# --- [ cleanupret ] -----------------------------------------------------------

# https://llvm.org/docs/LangRef.html#cleanupret-instruction

# ref: ParseCleanupRet
#
#   ::= 'cleanupret' from Value unwind ('to' 'caller' | TypeAndValue)

CleanupRetTerm -> CleanupRetTerm
	: 'cleanupret' 'from' CleanupPad=Value 'unwind' UnwindTarget Metadata=(',' MetadataAttachment)+?
;

# --- [ unreachable ] ----------------------------------------------------------

# https://llvm.org/docs/LangRef.html#unreachable-instruction

# ref: ParseInstruction

UnreachableTerm -> UnreachableTerm
	: 'unreachable' Metadata=(',' MetadataAttachment)+?
;

# === [ Metadata Nodes and Metadata Strings ] ==================================

# https://llvm.org/docs/LangRef.html#metadata-nodes-and-metadata-strings

# --- [ Metadata Tuple ] -------------------------------------------------------

# ref: ParseMDTuple

# ref: ParseMDNodeVector
#
#   ::= { Element (',' Element)* }
#  Element
#   ::= 'null' | TypeAndValue

# ref: ParseMDField(MDFieldList &)

# TODO: inline MDFields when Textmapper supports declarative inlining.

# ref: ParseMDField(MDField &)

MDTuple -> MDTuple
	: '!' '{' MDFields=(MDField separator',')* '}'
;

%interface MDField;

MDField -> MDField
	# Null is a special case since it is typeless.
	: NullLit
	| Metadata
;

# --- [ Metadata ] -------------------------------------------------------------

# ref: ParseMetadata
#
#  ::= i32 %local
#  ::= i32 @global
#  ::= i32 7
#  ::= !42
#  ::= !{...}
#  ::= !'string'
#  ::= !DILocation(...)

%interface Metadata;

Metadata -> Metadata
	: TypeValue
	| MDString
	# !{ ... }
	| MDTuple
	# !7
	| MetadataID
	| SpecializedMDNode
;

# --- [ Metadata String ] ------------------------------------------------------

# ref: ParseMDString
#
#   ::= '!' STRINGCONSTANT

MDString -> MDString
	: '!' Val=StringLit
;

# --- [ Metadata Attachment ] --------------------------------------------------

# ref: ParseMetadataAttachment
#
#   ::= !dbg !42

MetadataAttachment -> MetadataAttachment
	: Name=MetadataName MDNode
;

# --- [ Metadata Node ] --------------------------------------------------------

# ref: ParseMDNode
#
#  ::= !{ ... }
#  ::= !7
#  ::= !DILocation(...)

%interface MDNode;

MDNode -> MDNode
	# !{ ... }
	: MDTuple
	# !42
	| MetadataID
	| SpecializedMDNode
;

# --- [ Specialized Metadata Nodes ] -------------------------------------------

# https://llvm.org/docs/LangRef.html#specialized-metadata-nodes

# ref: ParseSpecializedMDNode

%interface SpecializedMDNode;

SpecializedMDNode -> SpecializedMDNode
	: DIBasicType
	| DICommonBlock # not in spec as of 2019-12-05
	| DICompileUnit
	| DICompositeType
	| DIDerivedType
	| DIEnumerator
	| DIExpression
	| DIFile
	| DIGlobalVariable
	| DIGlobalVariableExpression
	| DIImportedEntity
	| DILabel # not in spec as of 2018-10-14, still not in spec as of 2019-12-05
	| DILexicalBlock
	| DILexicalBlockFile
	| DILocalVariable
	| DILocation
	| DIMacro
	| DIMacroFile
	| DIModule # not in spec as of 2018-02-21, still not in spec as of 2019-12-05
	| DINamespace
	| DIObjCProperty
	| DISubprogram
	| DISubrange
	| DISubroutineType
	| DITemplateTypeParameter
	| DITemplateValueParameter
	| GenericDINode # not in spec as of 2018-02-21, still not in spec as of 2019-12-05
;

# ~~~ [ DIBasicType ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#dibasictype

# ref: ParseDIBasicType
#
#   ::= !DIBasicType(tag: DW_TAG_base_type, name: "int", size: 32, align: 32,
#                    encoding: DW_ATE_encoding, flags: 0)
#
#  OPTIONAL(tag, DwarfTagField, (dwarf::DW_TAG_base_type));
#  OPTIONAL(name, MDStringField, );
#  OPTIONAL(size, MDUnsignedField, (0, UINT64_MAX));
#  OPTIONAL(align, MDUnsignedField, (0, UINT32_MAX));
#  OPTIONAL(encoding, DwarfAttEncodingField, );
#  OPTIONAL(flags, DIFlagField, );

DIBasicType -> DIBasicType
	: '!DIBasicType' '(' Fields=(DIBasicTypeField separator ',')* ')'
;

%interface DIBasicTypeField;

DIBasicTypeField -> DIBasicTypeField
	: TagField
	| NameField
	| SizeField
	| AlignField
	| EncodingField
	| FlagsField
;

# ~~~ [ DICommonBlock ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# TODO: add link to LangRef.html.

# ref: ParseDICommonBlock
#
#   ::= !DICommonBlock(scope: !0, file: !2, name: "COMMON name", line: 9)
#
#  REQUIRED(scope, MDField, );
#  OPTIONAL(declaration, MDField, );
#  OPTIONAL(name, MDStringField, );
#  OPTIONAL(file, MDField, );
#  OPTIONAL(line, LineField, );

DICommonBlock -> DICommonBlock
	: '!DICommonBlock' '(' Fields=(DICommonBlockField separator ',')* ')'
;

%interface DICommonBlockField;

DICommonBlockField -> DICommonBlockField
	: ScopeField
	| DeclarationField
	| NameField
	| FileField
	| LineField
;

# ~~~ [ DICompileUnit ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#dicompileunit

# ref: ParseDICompileUnit
#
#   ::= !DICompileUnit(language: DW_LANG_C99, file: !0, producer: "clang",
#                      isOptimized: true, flags: "-O2", runtimeVersion: 1,
#                      splitDebugFilename: "abc.debug",
#                      emissionKind: FullDebug, enums: !1, retainedTypes: !2,
#                      globals: !4, imports: !5, macros: !6, dwoId: 0x0abcd)
#
#  REQUIRED(language, DwarfLangField, );
#  REQUIRED(file, MDField, (/* AllowNull */ false));
#  OPTIONAL(producer, MDStringField, );
#  OPTIONAL(isOptimized, MDBoolField, );
#  OPTIONAL(flags, MDStringField, );
#  OPTIONAL(runtimeVersion, MDUnsignedField, (0, UINT32_MAX));
#  OPTIONAL(splitDebugFilename, MDStringField, );
#  OPTIONAL(emissionKind, EmissionKindField, );
#  OPTIONAL(enums, MDField, );
#  OPTIONAL(retainedTypes, MDField, );
#  OPTIONAL(globals, MDField, );
#  OPTIONAL(imports, MDField, );
#  OPTIONAL(macros, MDField, );
#  OPTIONAL(dwoId, MDUnsignedField, );
#  OPTIONAL(splitDebugInlining, MDBoolField, = true);
#  OPTIONAL(debugInfoForProfiling, MDBoolField, = false);
#  OPTIONAL(nameTableKind, NameTableKindField, );
#  OPTIONAL(debugBaseAddress, MDBoolField, = false);

DICompileUnit -> DICompileUnit
	: '!DICompileUnit' '(' Fields=(DICompileUnitField separator ',')* ')'
;

%interface DICompileUnitField;

DICompileUnitField -> DICompileUnitField
	: LanguageField
	| FileField
	| ProducerField
	| IsOptimizedField
	| FlagsStringField
	| RuntimeVersionField
	| SplitDebugFilenameField
	| EmissionKindField
	| EnumsField
	| RetainedTypesField
	| GlobalsField
	| ImportsField
	| MacrosField
	| DwoIdField
	| SplitDebugInliningField
	| DebugInfoForProfilingField
	| NameTableKindField
	| DebugBaseAddressField
;

# ~~~ [ DICompositeType ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#dicompositetype

# ref: ParseDICompositeType
#
#  REQUIRED(tag, DwarfTagField, );
#  OPTIONAL(name, MDStringField, );
#  OPTIONAL(scope, MDField, );
#  OPTIONAL(file, MDField, );
#  OPTIONAL(line, LineField, );
#  OPTIONAL(baseType, MDField, );
#  OPTIONAL(size, MDUnsignedField, (0, UINT64_MAX));
#  OPTIONAL(align, MDUnsignedField, (0, UINT32_MAX));
#  OPTIONAL(offset, MDUnsignedField, (0, UINT64_MAX));
#  OPTIONAL(flags, DIFlagField, );
#  OPTIONAL(elements, MDField, );
#  OPTIONAL(runtimeLang, DwarfLangField, );
#  OPTIONAL(vtableHolder, MDField, );
#  OPTIONAL(templateParams, MDField, );
#  OPTIONAL(identifier, MDStringField, );
#  OPTIONAL(discriminator, MDField, );

DICompositeType -> DICompositeType
	: '!DICompositeType' '(' Fields=(DICompositeTypeField separator ',')* ')'
;

%interface DICompositeTypeField;

DICompositeTypeField -> DICompositeTypeField
	: TagField
	| NameField
	| ScopeField
	| FileField
	| LineField
	| BaseTypeField
	| SizeField
	| AlignField
	| OffsetField
	| FlagsField
	| ElementsField
	| RuntimeLangField
	| VtableHolderField
	| TemplateParamsField
	| IdentifierField
	| DiscriminatorField
	| DataLocationField
;

# ~~~ [ DIDerivedType ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#diderivedtype

# ref: ParseDIDerivedType
#
#   ::= !DIDerivedType(tag: DW_TAG_pointer_type, name: 'int', file: !0,
#                      line: 7, scope: !1, baseType: !2, size: 32,
#                      align: 32, offset: 0, flags: 0, extraData: !3,
#                      dwarfAddressSpace: 3)
#
#  REQUIRED(tag, DwarfTagField, );
#  OPTIONAL(name, MDStringField, );
#  OPTIONAL(scope, MDField, );
#  OPTIONAL(file, MDField, );
#  OPTIONAL(line, LineField, );
#  REQUIRED(baseType, MDField, );
#  OPTIONAL(size, MDUnsignedField, (0, UINT64_MAX));
#  OPTIONAL(align, MDUnsignedField, (0, UINT32_MAX));
#  OPTIONAL(offset, MDUnsignedField, (0, UINT64_MAX));
#  OPTIONAL(flags, DIFlagField, );
#  OPTIONAL(extraData, MDField, );
#  OPTIONAL(dwarfAddressSpace, MDUnsignedField, (UINT32_MAX, UINT32_MAX));

DIDerivedType -> DIDerivedType
	: '!DIDerivedType' '(' Fields=(DIDerivedTypeField separator ',')* ')'
;

%interface DIDerivedTypeField;

DIDerivedTypeField -> DIDerivedTypeField
	: TagField
	| NameField
	| ScopeField
	| FileField
	| LineField
	| BaseTypeField
	| SizeField
	| AlignField
	| OffsetField
	| FlagsField
	| ExtraDataField
	| DwarfAddressSpaceField
;

# ~~~ [ DIEnumerator ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#dienumerator

# ref: ParseDIEnumerator
#
#   ::= !DIEnumerator(value: 30, isUnsigned: true, name: 'SomeKind')
#
#  REQUIRED(name, MDStringField, );
#  REQUIRED(value, MDSignedOrUnsignedField, );
#  OPTIONAL(isUnsigned, MDBoolField, (false));

DIEnumerator -> DIEnumerator
	: '!DIEnumerator' '(' Fields=(DIEnumeratorField separator ',')* ')'
;

%interface DIEnumeratorField;

DIEnumeratorField -> DIEnumeratorField
	: NameField
	| ValueIntField
	| IsUnsignedField
;

# ~~~ [ DIExpression ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#diexpression

# ref: ParseDIExpression
#
#   ::= !DIExpression(0, 7, -1)

DIExpression -> DIExpression
	: '!DIExpression' '(' Fields=(DIExpressionField separator ',')* ')'
;

%interface DIExpressionField;

DIExpressionField -> DIExpressionField
	: UintLit
	| DwarfAttEncoding
	| DwarfOp
;

# ~~~ [ DIFile ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#difile

# ref: ParseDIFileType
#
#   ::= !DIFileType(filename: "path/to/file", directory: "/path/to/dir",
#                   checksumkind: CSK_MD5,
#                   checksum: "000102030405060708090a0b0c0d0e0f",
#                   source: "source file contents")
#
#  REQUIRED(filename, MDStringField, );
#  REQUIRED(directory, MDStringField, );
#  OPTIONAL(checksumkind, ChecksumKindField, (DIFile::CSK_MD5));
#  OPTIONAL(checksum, MDStringField, );
#  OPTIONAL(source, MDStringField, );

DIFile -> DIFile
	: '!DIFile' '(' Fields=(DIFileField separator ',')* ')'
;

%interface DIFileField;

DIFileField -> DIFileField
	: FilenameField
	| DirectoryField
	| ChecksumkindField
	| ChecksumField
	| SourceField
;

# ~~~ [ DIGlobalVariable ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#diglobalvariable

# ref: ParseDIGlobalVariable
#
#   ::= !DIGlobalVariable(scope: !0, name: "foo", linkageName: "foo",
#                         file: !1, line: 7, type: !2, isLocal: false,
#                         isDefinition: true, templateParams: !3,
#                         declaration: !4, align: 8)
#
#  REQUIRED(name, MDStringField, (AllowEmpty false));
#  OPTIONAL(scope, MDField, );
#  OPTIONAL(linkageName, MDStringField, );
#  OPTIONAL(file, MDField, );
#  OPTIONAL(line, LineField, );
#  OPTIONAL(type, MDField, );
#  OPTIONAL(isLocal, MDBoolField, );
#  OPTIONAL(isDefinition, MDBoolField, (true));
#  OPTIONAL(templateParams, MDField, );
#  OPTIONAL(declaration, MDField, );
#  OPTIONAL(align, MDUnsignedField, (0, UINT32_MAX));

DIGlobalVariable -> DIGlobalVariable
	: '!DIGlobalVariable' '(' Fields=(DIGlobalVariableField separator ',')* ')'
;

%interface DIGlobalVariableField;

DIGlobalVariableField -> DIGlobalVariableField
	: NameField
	| ScopeField
	| LinkageNameField
	| FileField
	| LineField
	| TypeField
	| IsLocalField
	| IsDefinitionField
	| TemplateParamsField
	| DeclarationField
	| AlignField
;

# ~~~ [ DIGlobalVariableExpression ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#diglobalvariableexpression

# ref: ParseDIGlobalVariableExpression
#
#   ::= !DIGlobalVariableExpression(var: !0, expr: !1)
#
#  REQUIRED(var, MDField, );
#  REQUIRED(expr, MDField, );

DIGlobalVariableExpression -> DIGlobalVariableExpression
	: '!DIGlobalVariableExpression' '(' Fields=(DIGlobalVariableExpressionField separator ',')* ')'
;

%interface DIGlobalVariableExpressionField;

DIGlobalVariableExpressionField -> DIGlobalVariableExpressionField
	: VarField
	| ExprField
;

# ~~~ [ DIImportedEntity ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#diimportedentity

# ref: ParseDIImportedEntity
#
#   ::= !DIImportedEntity(tag: DW_TAG_imported_module, scope: !0, entity: !1,
#                         line: 7, name: 'foo')
#
#  REQUIRED(tag, DwarfTagField, );
#  REQUIRED(scope, MDField, );
#  OPTIONAL(entity, MDField, );
#  OPTIONAL(file, MDField, );
#  OPTIONAL(line, LineField, );
#  OPTIONAL(name, MDStringField, );

DIImportedEntity -> DIImportedEntity
	: '!DIImportedEntity' '(' Fields=(DIImportedEntityField separator ',')* ')'
;

%interface DIImportedEntityField;

DIImportedEntityField -> DIImportedEntityField
	: TagField
	| ScopeField
	| EntityField
	| FileField
	| LineField
	| NameField
;

# ~~~ [ DILabel ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# TODO: add link to LangRef.html.

# ref: ParseDILabel:
#
#   ::= !DILabel(scope: !0, name: "foo", file: !1, line: 7)
#
#  REQUIRED(scope, MDField, (/* AllowNull */ false));
#  REQUIRED(name, MDStringField, );
#  REQUIRED(file, MDField, );
#  REQUIRED(line, LineField, );

DILabel -> DILabel
	: '!DILabel' '(' Fields=(DILabelField separator ',')* ')'
;

%interface DILabelField;

DILabelField -> DILabelField
	: ScopeField
	| NameField
	| FileField
	| LineField
;

# ~~~ [ DILexicalBlock ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#dilexicalblock

# ref: ParseDILexicalBlock
#
#   ::= !DILexicalBlock(scope: !0, file: !2, line: 7, column: 9)
#
#  REQUIRED(scope, MDField, (AllowNull false));
#  OPTIONAL(file, MDField, );
#  OPTIONAL(line, LineField, );
#  OPTIONAL(column, ColumnField, );

DILexicalBlock -> DILexicalBlock
	: '!DILexicalBlock' '(' Fields=(DILexicalBlockField separator ',')* ')'
;

%interface DILexicalBlockField;

DILexicalBlockField -> DILexicalBlockField
	: ScopeField
	| FileField
	| LineField
	| ColumnField
;

# ~~~ [ DILexicalBlockFile ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#dilexicalblockfile

# ref: ParseDILexicalBlockFile
#
#   ::= !DILexicalBlockFile(scope: !0, file: !2, discriminator: 9)
#
#  REQUIRED(scope, MDField, (AllowNull false));
#  OPTIONAL(file, MDField, );
#  REQUIRED(discriminator, MDUnsignedField, (0, UINT32_MAX));

DILexicalBlockFile -> DILexicalBlockFile
	: '!DILexicalBlockFile' '(' Fields=(DILexicalBlockFileField separator ',')* ')'
;

%interface DILexicalBlockFileField;

DILexicalBlockFileField -> DILexicalBlockFileField
	: ScopeField
	| FileField
	| DiscriminatorIntField
;

# ~~~ [ DILocalVariable ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#dilocalvariable

# ref: ParseDILocalVariable
#
#   ::= !DILocalVariable(arg: 7, scope: !0, name: 'foo',
#                        file: !1, line: 7, type: !2, arg: 2, flags: 7,
#                        align: 8)
#   ::= !DILocalVariable(scope: !0, name: 'foo',
#                        file: !1, line: 7, type: !2, arg: 2, flags: 7,
#                        align: 8)
#
#  REQUIRED(scope, MDField, (/* AllowNull */ false));
#  OPTIONAL(name, MDStringField, );
#  OPTIONAL(arg, MDUnsignedField, (0, UINT16_MAX));
#  OPTIONAL(file, MDField, );
#  OPTIONAL(line, LineField, );
#  OPTIONAL(type, MDField, );
#  OPTIONAL(flags, DIFlagField, );
#  OPTIONAL(align, MDUnsignedField, (0, UINT32_MAX));

DILocalVariable -> DILocalVariable
	: '!DILocalVariable' '(' Fields=(DILocalVariableField separator ',')* ')'
;

%interface DILocalVariableField;

DILocalVariableField -> DILocalVariableField
	: ScopeField
	| NameField
	| ArgField
	| FileField
	| LineField
	| TypeField
	| FlagsField
	| AlignField
;

# ~~~ [ DILocation ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#dilocation

# ref: ParseDILocation
#
#   ::= !DILocation(line: 43, column: 8, scope: !5, inlinedAt: !6,
#   isImplicitCode: true)
#
#  OPTIONAL(line, LineField, );
#  OPTIONAL(column, ColumnField, );
#  REQUIRED(scope, MDField, (AllowNull false));
#  OPTIONAL(inlinedAt, MDField, );
#  OPTIONAL(isImplicitCode, MDBoolField, (false));

DILocation -> DILocation
	: '!DILocation' '(' Fields=(DILocationField separator ',')* ')'
;

%interface DILocationField;

DILocationField -> DILocationField
	: LineField
	| ColumnField
	| ScopeField
	| InlinedAtField
	| IsImplicitCodeField
;

# ~~~ [ DIMacro ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#dimacro

# ref: ParseDIMacro
#
#   ::= !DIMacro(macinfo: type, line: 9, name: 'SomeMacro', value: 'SomeValue')
#
#  REQUIRED(type, DwarfMacinfoTypeField, );
#  OPTIONAL(line, LineField, );
#  REQUIRED(name, MDStringField, );
#  OPTIONAL(value, MDStringField, );

DIMacro -> DIMacro
	: '!DIMacro' '(' Fields=(DIMacroField separator ',')* ')'
;

%interface DIMacroField;

DIMacroField -> DIMacroField
	: TypeMacinfoField
	| LineField
	| NameField
	| ValueStringField
;

# ~~~ [ DIMacroFile ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#dimacrofile

# ref: ParseDIMacroFile
#
#   ::= !DIMacroFile(line: 9, file: !2, nodes: !3)
#
#  OPTIONAL(type, DwarfMacinfoTypeField, (dwarf::DW_MACINFO_start_file));
#  OPTIONAL(line, LineField, );
#  REQUIRED(file, MDField, );
#  OPTIONAL(nodes, MDField, );

DIMacroFile -> DIMacroFile
	: '!DIMacroFile' '(' Fields=(DIMacroFileField separator ',')* ')'
;

%interface DIMacroFileField;

DIMacroFileField -> DIMacroFileField
	: TypeMacinfoField
	| LineField
	| FileField
	| NodesField
;

# ~~~ [ DIModule ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# TODO: add link to LangRef.html.

# ref: ParseDIModule
#
#   ::= !DIModule(scope: !0, name: "SomeModule", configMacros:
#   "-DNDEBUG", includePath: "/usr/include", apinotes: "module.apinotes",
#   file: !1, line: 4)
#
#  REQUIRED(scope, MDField, );
#  REQUIRED(name, MDStringField, );
#  OPTIONAL(configMacros, MDStringField, );
#  OPTIONAL(includePath, MDStringField, );
#  OPTIONAL(apinotes, MDStringField, );
#  OPTIONAL(file, MDField, );
#  OPTIONAL(line, LineField, );

DIModule -> DIModule
	: '!DIModule' '(' Fields=(DIModuleField separator ',')* ')'
;

%interface DIModuleField;

DIModuleField -> DIModuleField
	: ScopeField
	| NameField
	| ConfigMacrosField
	| IncludePathField
	| APINotesField
	| FileField
	| LineField
;

# ~~~ [ DINamespace ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#dinamespace

# ref: ParseDINamespace
#
#   ::= !DINamespace(scope: !0, file: !2, name: 'SomeNamespace', line: 9)
#
#  REQUIRED(scope, MDField, );
#  OPTIONAL(name, MDStringField, );
#  OPTIONAL(exportSymbols, MDBoolField, );

DINamespace -> DINamespace
	: '!DINamespace' '(' Fields=(DINamespaceField separator ',')* ')'
;

%interface DINamespaceField;

DINamespaceField -> DINamespaceField
	: ScopeField
	| NameField
	| ExportSymbolsField
;

# ~~~ [ DIObjCProperty ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#diobjcproperty

# ref: ParseDIObjCProperty
#
#   ::= !DIObjCProperty(name: 'foo', file: !1, line: 7, setter: 'setFoo',
#                       getter: 'getFoo', attributes: 7, type: !2)
#
#  OPTIONAL(name, MDStringField, );
#  OPTIONAL(file, MDField, );
#  OPTIONAL(line, LineField, );
#  OPTIONAL(setter, MDStringField, );
#  OPTIONAL(getter, MDStringField, );
#  OPTIONAL(attributes, MDUnsignedField, (0, UINT32_MAX));
#  OPTIONAL(type, MDField, );

DIObjCProperty -> DIObjCProperty
	: '!DIObjCProperty' '(' Fields=(DIObjCPropertyField separator ',')* ')'
;

%interface DIObjCPropertyField;

DIObjCPropertyField -> DIObjCPropertyField
	: NameField
	| FileField
	| LineField
	| SetterField
	| GetterField
	| AttributesField
	| TypeField
;

# ~~~ [ DISubprogram ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#disubprogram

# ref: ParseDISubprogram
#
#   ::= !DISubprogram(scope: !0, name: "foo", linkageName: "_Zfoo",
#                     file: !1, line: 7, type: !2, isLocal: false,
#                     isDefinition: true, scopeLine: 8, containingType: !3,
#                     virtuality: DW_VIRTUALTIY_pure_virtual,
#                     virtualIndex: 10, thisAdjustment: 4, flags: 11,
#                     isOptimized: false, templateParams: !4, declaration: !5,
#                     retainedNodes: !6, thrownTypes: !7)
#
#  OPTIONAL(scope, MDField, );
#  OPTIONAL(name, MDStringField, );
#  OPTIONAL(linkageName, MDStringField, );
#  OPTIONAL(file, MDField, );
#  OPTIONAL(line, LineField, );
#  OPTIONAL(type, MDField, );
#  OPTIONAL(isLocal, MDBoolField, );
#  OPTIONAL(isDefinition, MDBoolField, (true));
#  OPTIONAL(scopeLine, LineField, );
#  OPTIONAL(containingType, MDField, );
#  OPTIONAL(virtuality, DwarfVirtualityField, );
#  OPTIONAL(virtualIndex, MDUnsignedField, (0, UINT32_MAX));
#  OPTIONAL(thisAdjustment, MDSignedField, (0, INT32_MIN, INT32_MAX));
#  OPTIONAL(flags, DIFlagField, );
#  OPTIONAL(isOptimized, MDBoolField, );
#  OPTIONAL(unit, MDField, );
#  OPTIONAL(templateParams, MDField, );
#  OPTIONAL(declaration, MDField, );
#  OPTIONAL(retainedNodes, MDField, );
#  OPTIONAL(thrownTypes, MDField, );

DISubprogram -> DISubprogram
	: '!DISubprogram' '(' Fields=(DISubprogramField separator ',')* ')'
;

%interface DISubprogramField;

DISubprogramField -> DISubprogramField
	: ScopeField
	| NameField
	| LinkageNameField
	| FileField
	| LineField
	| TypeField
	| IsLocalField
	| IsDefinitionField
	| ScopeLineField
	| ContainingTypeField
	| VirtualityField
	| VirtualIndexField
	| ThisAdjustmentField
	| FlagsField
	| SPFlagsField
	| IsOptimizedField
	| UnitField
	| TemplateParamsField
	| DeclarationField
	| RetainedNodesField
	| ThrownTypesField
;

# ~~~ [ DISubrange ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#disubrange

# ref: ParseDISubrange
#
#   ::= !DISubrange(count: 30, lowerBound: 2)
#   ::= !DISubrange(count: !node, lowerBound: 2)
#   ::= !DISubrange(lowerBound: !node1, upperBound: !node2, stride: !node3)
#
#  OPTIONAL(count, MDSignedOrMDField, (-1, -1, INT64_MAX, false));
#  OPTIONAL(lowerBound, MDSignedOrMDField, );
#  OPTIONAL(upperBound, MDSignedOrMDField, );
#  OPTIONAL(stride, MDSignedOrMDField, );

DISubrange -> DISubrange
	: '!DISubrange' '(' Fields=(DISubrangeField separator ',')* ')'
;

%interface DISubrangeField;

DISubrangeField -> DISubrangeField
	: CountField
	| LowerBoundField
	| UpperBoundField
	| StrideField
;

# ~~~ [ DISubroutineType ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#disubroutinetype

# ref: ParseDISubroutineType
#
#  OPTIONAL(flags, DIFlagField, );
#  OPTIONAL(cc, DwarfCCField, );
#  REQUIRED(types, MDField, );

DISubroutineType -> DISubroutineType
	: '!DISubroutineType' '(' Fields=(DISubroutineTypeField separator ',')* ')'
;

%interface DISubroutineTypeField;

DISubroutineTypeField -> DISubroutineTypeField
	: FlagsField
	| CCField
	| TypesField
;

# ~~~ [ DITemplateTypeParameter ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#ditemplatetypeparameter

# ref: ParseDITemplateTypeParameter
#
#   ::= !DITemplateTypeParameter(name: 'Ty', type: !1)
#
#  OPTIONAL(name, MDStringField, );
#  REQUIRED(type, MDField, );

DITemplateTypeParameter -> DITemplateTypeParameter
	: '!DITemplateTypeParameter' '(' Fields=(DITemplateTypeParameterField separator ',')* ')'
;

%interface DITemplateTypeParameterField;

DITemplateTypeParameterField -> DITemplateTypeParameterField
	: NameField
	| TypeField
;

# ~~~ [ DITemplateValueParameter ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# https://llvm.org/docs/LangRef.html#ditemplatevalueparameter

# ref: ParseDITemplateValueParameter
#
#   ::= !DITemplateValueParameter(tag: DW_TAG_template_value_parameter,
#                                 name: 'V', type: !1, value: i32 7)
#
#  OPTIONAL(tag, DwarfTagField, (dwarf::DW_TAG_template_value_parameter));
#  OPTIONAL(name, MDStringField, );
#  OPTIONAL(type, MDField, );
#  REQUIRED(value, MDField, );

DITemplateValueParameter -> DITemplateValueParameter
	: '!DITemplateValueParameter' '(' Fields=(DITemplateValueParameterField separator ',')* ')'
;

%interface DITemplateValueParameterField;

DITemplateValueParameterField -> DITemplateValueParameterField
	: TagField
	| NameField
	| TypeField
	| ValueField
;

# ~~~ [ GenericDINode ] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# TODO: add link to LangRef.html.

# ref: ParseGenericDINode
#
#   ::= !GenericDINode(tag: 15, header: '...', operands: {...})
#
#  REQUIRED(tag, DwarfTagField, );
#  OPTIONAL(header, MDStringField, );
#  OPTIONAL(operands, MDFieldList, );

GenericDINode -> GenericDINode
	: '!GenericDINode' '(' Fields=(GenericDINodeField separator ',')* ')'
;

%interface GenericDINodeField;

GenericDINodeField -> GenericDINodeField
	: TagField
	| HeaderField
	| OperandsField
;

# ___ [ Specialized metadata fields ] __________________________________________

AlignField -> AlignField
	: 'align:' Align=UintLit
;

ArgField -> ArgField
	: 'arg:' Arg=UintLit
;

AttributesField -> AttributesField
	: 'attributes:' Attributes=UintLit
;

BaseTypeField -> BaseTypeField
	: 'baseType:' BaseType=MDField
;

CCField -> CCField
	: 'cc:' CC=DwarfCC
;

ChecksumField -> ChecksumField
	: 'checksum:' Checksum=StringLit
;

ChecksumkindField -> ChecksumkindField
	: 'checksumkind:' Checksumkind=ChecksumKind
;

ColumnField -> ColumnField
	: 'column:' Column=IntLit
;

ConfigMacrosField -> ConfigMacrosField
	: 'configMacros:' ConfigMacros=StringLit
;

ContainingTypeField -> ContainingTypeField
	: 'containingType:' ContainingType=MDField
;

CountField -> CountField
	: 'count:' Count=MDFieldOrInt
;

DebugBaseAddressField -> DebugBaseAddressField
	: 'debugBaseAddress:' DebugBaseAddress=BoolLit
;

DebugInfoForProfilingField -> DebugInfoForProfilingField
	: 'debugInfoForProfiling:' DebugInfoForProfiling=BoolLit
;

DeclarationField -> DeclarationField
	: 'declaration:' Declaration=MDField
;

DirectoryField -> DirectoryField
	: 'directory:' Directory=StringLit
;

DiscriminatorField -> DiscriminatorField
	: 'discriminator:' Discriminator=MDField
;


DataLocationField -> DataLocationField
	: 'dataLocation:' DataLocation=MDField
;

DiscriminatorIntField -> DiscriminatorIntField
	: 'discriminator:' Discriminator=UintLit
;

DwarfAddressSpaceField -> DwarfAddressSpaceField
	: 'dwarfAddressSpace:' DwarfAddressSpace=UintLit
;

DwoIdField -> DwoIdField
	: 'dwoId:' DwoId=UintLit
;

ElementsField -> ElementsField
	: 'elements:' Elements=MDField
;

EmissionKindField -> EmissionKindField
	: 'emissionKind:' EmissionKind=EmissionKind
;

EncodingField -> EncodingField
	: 'encoding:' Encoding=DwarfAttEncodingOrUint
;

EntityField -> EntityField
	: 'entity:' Entity=MDField
;

EnumsField -> EnumsField
	: 'enums:' Enums=MDField
;

ExportSymbolsField -> ExportSymbolsField
	: 'exportSymbols:' ExportSymbols=BoolLit
;

ExprField -> ExprField
	: 'expr:' Expr=MDField
;

ExtraDataField -> ExtraDataField
	: 'extraData:' ExtraData=MDField
;

FileField -> FileField
	: 'file:' File=MDField
;

FilenameField -> FilenameField
	: 'filename:' Filename=StringLit
;

FlagsField -> FlagsField
	: 'flags:' Flags=DIFlags
;

FlagsStringField -> FlagsStringField
	: 'flags:' Flags=StringLit
;

GetterField -> GetterField
	: 'getter:' Getter=StringLit
;

GlobalsField -> GlobalsField
	: 'globals:' Globals=MDField
;

HeaderField -> HeaderField
	: 'header:' Header=StringLit
;

IdentifierField -> IdentifierField
	: 'identifier:' Identifier=StringLit
;

ImportsField -> ImportsField
	: 'imports:' Imports=MDField
;

IncludePathField -> IncludePathField
	: 'includePath:' IncludePath=StringLit
;

InlinedAtField -> InlinedAtField
	: 'inlinedAt:' InlinedAt=MDField
;

IsDefinitionField -> IsDefinitionField
	: 'isDefinition:' IsDefinition=BoolLit
;

IsImplicitCodeField -> IsImplicitCodeField
	: 'isImplicitCode:' IsImplicitCode=BoolLit
;

IsLocalField -> IsLocalField
	: 'isLocal:' IsLocal=BoolLit
;

IsOptimizedField -> IsOptimizedField
	: 'isOptimized:' IsOptimized=BoolLit
;

IsUnsignedField -> IsUnsignedField
	: 'isUnsigned:' IsUnsigned=BoolLit
;

APINotesField -> APINotesField
	: 'apinotes:' APINotes=StringLit
;

LanguageField -> LanguageField
	: 'language:' Language=DwarfLang
;

LineField -> LineField
	: 'line:' Line=IntLit
;

LinkageNameField -> LinkageNameField
	: 'linkageName:' LinkageName=StringLit
;

LowerBoundField -> LowerBoundField
	: 'lowerBound:' LowerBound=MDFieldOrInt
;

MacrosField -> MacrosField
	: 'macros:' Macros=MDField
;

NameField -> NameField
	: 'name:' Name=StringLit
;

NameTableKindField -> NameTableKindField
	: 'nameTableKind:' NameTableKind=NameTableKind
;

NodesField -> NodesField
	: 'nodes:' Nodes=MDField
;

OffsetField -> OffsetField
	# TODO: rename OffsetField= attribute to Offset= when inspirer/textmapper#13 is resolved
	: 'offset:' OffsetField=UintLit
;

OperandsField -> OperandsField
	: 'operands:' '{' Operands=(MDField separator',')* '}'
;

ProducerField -> ProducerField
	: 'producer:' Producer=StringLit
;

RetainedNodesField -> RetainedNodesField
	: 'retainedNodes:' RetainedNodes=MDField
;

RetainedTypesField -> RetainedTypesField
	: 'retainedTypes:' RetainedTypes=MDField
;

RuntimeLangField -> RuntimeLangField
	: 'runtimeLang:' RuntimeLang=DwarfLang
;

RuntimeVersionField -> RuntimeVersionField
	: 'runtimeVersion:' RuntimeVersion=UintLit
;

ScopeField -> ScopeField
	: 'scope:' Scope=MDField
;

ScopeLineField -> ScopeLineField
	: 'scopeLine:' ScopeLine=IntLit
;

SetterField -> SetterField
	: 'setter:' Setter=StringLit
;

SizeField -> SizeField
	: 'size:' Size=UintLit
;

SourceField -> SourceField
	: 'source:' Source=StringLit
;

SPFlagsField -> SPFlagsField
	: 'spFlags:' SPFlags=DISPFlags
;

SplitDebugFilenameField -> SplitDebugFilenameField
	: 'splitDebugFilename:' SplitDebugFilename=StringLit
;

SplitDebugInliningField -> SplitDebugInliningField
	: 'splitDebugInlining:' SplitDebugInlining=BoolLit
;

StrideField -> StrideField
	: 'stride:' Stride=MDFieldOrInt
;

TagField -> TagField
	: 'tag:' Tag=DwarfTag
;

TemplateParamsField -> TemplateParamsField
	: 'templateParams:' TemplateParams=MDField
;

ThisAdjustmentField -> ThisAdjustmentField
	: 'thisAdjustment:' ThisAdjustment=IntLit
;

ThrownTypesField -> ThrownTypesField
	: 'thrownTypes:' ThrownTypes=MDField
;

TypeField -> TypeField
	: 'type:' Typ=MDField
;

TypeMacinfoField -> TypeMacinfoField
	: 'type:' Typ=DwarfMacinfo
;

TypesField -> TypesField
	: 'types:' Types=MDField
;

UnitField -> UnitField
	: 'unit:' Unit=MDField
;

UpperBoundField -> UpperBoundField
	: 'upperBound:' UpperBound=MDFieldOrInt
;

ValueField -> ValueField
	: 'value:' Value=MDField
;

ValueIntField -> ValueIntField
	: 'value:' Value=IntLit
;

ValueStringField -> ValueStringField
	: 'value:' Value=StringLit
;

VarField -> VarField
	: 'var:' Var=MDField
;

VirtualIndexField -> VirtualIndexField
	: 'virtualIndex:' VirtualIndex=UintLit
;

VirtualityField -> VirtualityField
	: 'virtuality:' Virtuality=DwarfVirtuality
;

VtableHolderField -> VtableHolderField
	: 'vtableHolder:' VtableHolder=MDField
;

# ___ [ Specialized metadata values ] __________________________________________

# ref: ParseMDField(MDSignedOrMDField &)

%interface MDFieldOrInt;

MDFieldOrInt -> MDFieldOrInt
	: MDField
	| IntLit
;

# ___ [ Specialized metadata enums ] ___________________________________________

ChecksumKind -> ChecksumKind
	# CSK_foo
	: checksum_kind_tok
;

# ref: ParseMDField(DIFlagField &)
#
#  ::= uint32
#  ::= DIFlagVector
#  ::= DIFlagVector pipe_tok DIFlagFwdDecl pipe_tok uint32 pipe_tok DIFlagPublic

DIFlags -> DIFlags
	: Flags=(DIFlag separator pipe_tok)+
;

%interface DIFlag;

DIFlag -> DIFlag
	# DIFlagFoo
	: di_flag_tok   -> DIFlagEnum
	| UintLit       -> DIFlagInt
;

# ref: ParseMDField(DISPFlagField &)
#
#  ::= uint32
#  ::= DISPFlagVector
#  ::= DISPFlagVector pipe_tok DISPFlag* pipe_tok uint32

DISPFlags -> DISPFlags
	: Flags=(DISPFlag separator pipe_tok)+
;

%interface DISPFlag;

DISPFlag -> DISPFlag
	# DISPFlagFoo
	: disp_flag_tok   -> DISPFlagEnum
	| UintLit         -> DISPFlagInt
;

# ref: ParseMDField(DwarfAttEncodingField &)

%interface DwarfAttEncoding;

DwarfAttEncoding -> DwarfAttEncoding
	# DW_ATE_foo
	: dwarf_att_encoding_tok   -> DwarfAttEncodingEnum
;

%interface DwarfAttEncodingOrUint;

DwarfAttEncodingOrUint -> DwarfAttEncodingOrUint
	# DW_ATE_foo
	: DwarfAttEncoding
	| UintLit            -> DwarfAttEncodingInt
;

# ref: ParseMDField(DwarfCCField &Result)

%interface DwarfCC;

DwarfCC -> DwarfCC
	# DW_CC_foo
	: dwarf_cc_tok   -> DwarfCCEnum
	| UintLit        -> DwarfCCInt
;

# ref: ParseMDField(DwarfLangField &)

%interface DwarfLang;

DwarfLang -> DwarfLang
	# DW_LANG_foo
	: dwarf_lang_tok   -> DwarfLangEnum
	| UintLit          -> DwarfLangInt
;

# ref: ParseMDField(DwarfMacinfoTypeField &)

%interface DwarfMacinfo;

DwarfMacinfo -> DwarfMacinfo
	# DW_MACINFO_foo
	: dwarf_macinfo_tok   -> DwarfMacinfoEnum
	| UintLit             -> DwarfMacinfoInt
;

DwarfOp -> DwarfOp
	# DW_OP_foo
	: dwarf_op_tok
;

# ref: ParseMDField(DwarfTagField &)

%interface DwarfTag;

DwarfTag -> DwarfTag
	# DW_TAG_foo
	: dwarf_tag_tok   -> DwarfTagEnum
	| UintLit         -> DwarfTagInt
;

# ref: ParseMDField(DwarfVirtualityField &)

%interface DwarfVirtuality;

DwarfVirtuality -> DwarfVirtuality
	# DW_VIRTUALITY_foo
	: dwarf_virtuality_tok   -> DwarfVirtualityEnum
	| UintLit                -> DwarfVirtualityInt
;

# ref bool LLParser::ParseMDField(EmissionKindField &)

%interface EmissionKind;

EmissionKind -> EmissionKind
	# FullDebug
	: emission_kind_tok   -> EmissionKindEnum
	| UintLit             -> EmissionKindInt
;

# ref: bool LLParser::ParseMDField(NameTableKindField &)

%interface NameTableKind;

NameTableKind -> NameTableKind
	# GNU
	: name_table_kind_tok   -> NameTableKindEnum
	| UintLit               -> NameTableKindInt
;

# ___ [ Helpers ] ______________________________________________________________

# ref: ParseOptionalAddrSpace
#
#   := empty
#   := 'addrspace' '(' uint32 ')'

AddrSpace -> AddrSpace
	: 'addrspace' '(' N=UintLit ')'
;

# ref: ParseOptionalAlignment
#
#   ::= empty
#   ::= 'align' 4

Align -> Align
	: 'align' N=UintLit
;

AlignPair -> AlignPair
	: 'align' '=' N=UintLit
;

# ref: ParseOptionalStackAlignment
#
#   ::= empty
#   ::= 'alignstack' '(' 4 ')'
AlignStack -> AlignStack
	: 'alignstack' '(' N=UintLit ')'
;

AlignStackPair -> AlignStackPair
	: 'alignstack' '=' N=UintLit
;

# ref: parseAllocSizeArguments

AllocSize -> AllocSize
	: 'allocsize' '(' ElemSizeIndex=UintLit ')'
	| 'allocsize' '(' ElemSizeIndex=UintLit ',' NElemsIndex=UintLit ')'
;

# ref: ParseParameterList
#
#    ::= '(' ')'
#    ::= '(' Arg (',' Arg)* ')'
#  Arg
#    ::= Type OptionalAttributes Value OptionalAttributes

# NOTE: Args may contain '...'. The ellipsis is purely for readability.

Args -> Args
	: '...'?
	| Args=(Arg separator ',')+ (',' '...')?
;

# ref: ParseMetadataAsValue
#
#  ::= metadata i32 %local
#  ::= metadata i32 @global
#  ::= metadata i32 7
#  ::= metadata !0
#  ::= metadata !{...}
#  ::= metadata !"string"

Arg -> Arg
	: Typ=ConcreteType Attrs=ParamAttribute* Val=Value
	| Typ=MetadataType Val=Metadata
;

Atomic -> Atomic
	: 'atomic'
;

# ref: ParseOrdering
#
#   ::= AtomicOrdering

AtomicOrdering -> AtomicOrdering
	: 'acq_rel'
	| 'acquire'
	| 'monotonic'
	| 'release'
	| 'seq_cst'
	| 'unordered'
;

AttrPair -> AttrPair
	: Key=StringLit '=' Val=StringLit
;

AttrString -> AttrString
	: Val=StringLit
;

# ref: ParseByValWithOptionalType
#
#   ::= byval
#   ::= byval(<ty>)

Byval -> Byval
	: 'byval'
	| 'byval' '(' Typ=Type ')'
;

# ref: ParseOptionalCallingConv
#
#   ::= empty
#   ::= 'ccc'
#   ::= 'fastcc'
#   ::= 'intel_ocl_bicc'
#   ::= 'coldcc'
#   ::= 'cfguard_checkcc'
#   ::= 'x86_stdcallcc'
#   ::= 'x86_fastcallcc'
#   ::= 'x86_thiscallcc'
#   ::= 'x86_vectorcallcc'
#   ::= 'arm_apcscc'
#   ::= 'arm_aapcscc'
#   ::= 'arm_aapcs_vfpcc'
#   ::= 'aarch64_vector_pcs'
#   ::= 'aarch64_sve_vector_pcs'
#   ::= 'msp430_intrcc'
#   ::= 'avr_intrcc'
#   ::= 'avr_signalcc'
#   ::= 'ptx_kernel'
#   ::= 'ptx_device'
#   ::= 'spir_func'
#   ::= 'spir_kernel'
#   ::= 'x86_64_sysvcc'
#   ::= 'win64cc'
#   ::= 'webkit_jscc'
#   ::= 'anyregcc'
#   ::= 'preserve_mostcc'
#   ::= 'preserve_allcc'
#   ::= 'ghccc'
#   ::= 'swiftcc'
#   ::= 'x86_intrcc'
#   ::= 'hhvmcc'
#   ::= 'hhvm_ccc'
#   ::= 'cxx_fast_tlscc'
#   ::= 'amdgpu_vs'
#   ::= 'amdgpu_ls'
#   ::= 'amdgpu_hs'
#   ::= 'amdgpu_es'
#   ::= 'amdgpu_gs'
#   ::= 'amdgpu_ps'
#   ::= 'amdgpu_cs'
#   ::= 'amdgpu_kernel'
#   ::= 'tailcc'
#   ::= 'cc' UINT

%interface CallingConv;

CallingConv -> CallingConv
	: CallingConvEnum
	| CallingConvInt
;

CallingConvEnum -> CallingConvEnum
	: 'aarch64_sve_vector_pcs'
	| 'aarch64_vector_pcs'
	| 'amdgpu_cs'
	| 'amdgpu_es'
	| 'amdgpu_gs'
	| 'amdgpu_hs'
	| 'amdgpu_kernel'
	| 'amdgpu_ls'
	| 'amdgpu_ps'
	| 'amdgpu_vs'
	| 'anyregcc'
	| 'arm_aapcs_vfpcc'
	| 'arm_aapcscc'
	| 'arm_apcscc'
	| 'avr_intrcc'
	| 'avr_signalcc'
	| 'ccc'
	| 'cfguard_checkcc'
	| 'coldcc'
	| 'cxx_fast_tlscc'
	| 'fastcc'
	| 'ghccc'
	| 'hhvm_ccc'
	| 'hhvmcc'
	| 'intel_ocl_bicc'
	| 'msp430_intrcc'
	| 'preserve_allcc'
	| 'preserve_mostcc'
	| 'ptx_device'
	| 'ptx_kernel'
	| 'spir_func'
	| 'spir_kernel'
	| 'swiftcc'
	| 'tailcc'
	| 'webkit_jscc'
	| 'win64cc'
	| 'x86_64_sysvcc'
	| 'x86_fastcallcc'
	| 'x86_intrcc'
	| 'x86_regcallcc'
	| 'x86_stdcallcc'
	| 'x86_thiscallcc'
	| 'x86_vectorcallcc'
;

CallingConvInt -> CallingConvInt
	: 'cc' UintLit
;

# ref: parseOptionalComdat

Comdat -> Comdat
	: 'comdat'
	| 'comdat' '(' Name=ComdatName ')'
;

# ref: ParseOptionalDerefAttrBytes
#
#   ::= empty
#   ::= AttrKind '(' 4 ')'

Dereferenceable -> Dereferenceable
	: 'dereferenceable' '(' N=UintLit ')'
	| 'dereferenceable_or_null' '(' N=UintLit ')'   -> DereferenceableOrNull
;

# https://llvm.org/docs/LangRef.html#dll-storage-classes

# ref: ParseOptionalDLLStorageClass
#
#   ::= empty
#   ::= 'dllimport'
#   ::= 'dllexport'

DLLStorageClass -> DLLStorageClass
	: 'dllexport'
	| 'dllimport'
;

Ellipsis -> Ellipsis
	: '...'
;

Exact -> Exact
	: 'exact'
;

# ref: ParseExceptionArgs

ExceptionArg -> ExceptionArg
	: Typ=ConcreteType Val=Value
	| Typ=MetadataType Val=Metadata
;

%interface ExceptionPad;

ExceptionPad -> ExceptionPad
	: NoneConst
	| LocalIdent
;

# ref: EatFastMathFlagsIfPresent

FastMathFlag -> FastMathFlag
	: 'afn'
	| 'arcp'
	| 'contract'
	| 'fast'
	| 'ninf'
	| 'nnan'
	| 'nsz'
	| 'reassoc'
;

# ref: ParseCmpPredicate

FPred -> FPred
	: 'false'
	| 'oeq'
	| 'oge'
	| 'ogt'
	| 'ole'
	| 'olt'
	| 'one'
	| 'ord'
	| 'true'
	| 'ueq'
	| 'uge'
	| 'ugt'
	| 'ule'
	| 'ult'
	| 'une'
	| 'uno'
;

# ref: ParseFnAttributeValuePairs
#
#   ::= <attr> | <attr> '=' <value>

# NOTE: FuncAttribute should contain Align. However, using LALR(1) this
# produces a reduce/reduce conflict as GlobalDecl also contains Align.

%interface FuncAttribute;

FuncAttribute -> FuncAttribute
	: AttrString
	| AttrPair
	# not used in attribute groups.
	| AttrGroupID
	# used in functions.
	#| Align # NOTE: removed to resolve reduce/reduce conflict, see above.
	# used in attribute groups.
	| AlignPair
	| AlignStack
	| AlignStackPair
	| AllocSize
	| FuncAttr
;

FuncAttr -> FuncAttr
	: 'alwaysinline'
	| 'argmemonly'
	| 'builtin'
	| 'cold'
	| 'convergent'
	| 'inaccessiblemem_or_argmemonly'
	| 'inaccessiblememonly'
	| 'inlinehint'
	| 'jumptable'
	| 'minsize'
	| 'naked'
	| 'nobuiltin'
	| 'nocf_check'
	| 'noduplicate'
	| 'nofree'
	| 'noimplicitfloat'
	| 'noinline'
	| 'nonlazybind'
	| 'norecurse'
	| 'noredzone'
	| 'noreturn'
	| 'nosync'
	| 'nounwind'
	| 'optforfuzzing'
	| 'optnone'
	| 'optsize'
	| 'readnone'
	| 'readonly'
	| 'returns_twice'
	| 'safestack'
	| 'sanitize_address'
	| 'sanitize_hwaddress'
	| 'sanitize_memory'
	| 'sanitize_memtag'
	| 'sanitize_thread'
	| 'shadowcallstack'
	| 'speculatable'
	| 'speculative_load_hardening'
	| 'ssp'
	| 'sspreq'
	| 'sspstrong'
	| 'strictfp'
	| 'uwtable'
	| 'willreturn'
	| 'writeonly'
;

InBounds -> InBounds
	: 'inbounds'
;

# ref: ParseCmpPredicate

IPred -> IPred
	: 'eq'
	| 'ne'
	| 'sge'
	| 'sgt'
	| 'sle'
	| 'slt'
	| 'uge'
	| 'ugt'
	| 'ule'
	| 'ult'
;

Label -> Label
	: Typ=LabelType Name=LocalIdent
;

# https://llvm.org/docs/LangRef.html#linkage-types

# ref: ParseOptionalLinkage
#
#   ::= empty
#   ::= 'private'
#   ::= 'internal'
#   ::= 'weak'
#   ::= 'weak_odr'
#   ::= 'linkonce'
#   ::= 'linkonce_odr'
#   ::= 'available_externally'
#   ::= 'appending'
#   ::= 'common'
#   ::= 'extern_weak'
#   ::= 'external'

# TODO: Check if it is possible to merge Linkage and ExternLinkage. Currently,
# this is not possible as it leads to shift/reduce conflicts (when merging
# GlobalDecl and GlobalDef). Perhaps when the parser generator is better capable
# at resolving conflicts.

Linkage -> Linkage
	: 'appending'
	| 'available_externally'
	| 'common'
	| 'internal'
	| 'linkonce'
	| 'linkonce_odr'
	| 'private'
	| 'weak'
	| 'weak_odr'
;

ExternLinkage -> ExternLinkage
	: 'extern_weak'
	| 'external'
;

OperandBundle -> OperandBundle
	: Tag=StringLit '(' Inputs=(TypeValue separator ',')* ')'
;

OverflowFlag -> OverflowFlag
	: 'nsw'
	| 'nuw'
;

# ref: ParseArgumentList
#
#   ::= '(' ArgTypeListI ')'
#  ArgTypeListI
#   ::= empty
#   ::= '...'
#   ::= ArgTypeList ',' '...'
#   ::= ArgType (',' ArgType)*

# NOTE: The grammar for Params of FuncType contains Attrs and Name. However, the
# semantic check will report an error if any of those are present in the input.

Params -> Params
	: Variadic=Ellipsisopt
	| Params=(Param separator ',')+ Variadic=(',' Ellipsis)?
;

Param -> Param
	: Typ=Type Attrs=ParamAttribute* Name=LocalIdent?
;

# ref: ParseOptionalParamAttrs

%interface ParamAttribute;

ParamAttribute -> ParamAttribute
	: AttrString
	| AttrPair
	| Align
	| Byval
	| Dereferenceable
	| ParamAttr
;

ParamAttr -> ParamAttr
	: 'immarg'
	| 'inalloca'
	| 'inreg'
	| 'nest'
	| 'noalias'
	| 'nocapture'
	| 'nofree'
	| 'nonnull'
	| 'readnone'
	| 'readonly'
	| 'returned'
	| 'signext'
	| 'sret'
	| 'swifterror'
	| 'swiftself'
	| 'writeonly'
	| 'zeroext'
;

Partition -> Partition
	: 'partition' Name=StringLit
;

# https://llvm.org/docs/LangRef.html#runtime-preemption-model

# ref: ParseOptionalDSOLocal

Preemption -> Preemption
	: 'dso_local'
	| 'dso_preemptable'
;

# ref: ParseOptionalReturnAttrs

%interface ReturnAttribute;

ReturnAttribute -> ReturnAttribute
	# TODO: Figure out how to re-enable without getting these errors in FuncHeader:
	#    - two unnamed fields share the same type `AttrPair`: ReturnAttribute -vs- FuncAttribute
	#    - `AttrPair` occurs in both named and unnamed fields
	#    - `ReturnAttrs` cannot be nullable, since it precedes FuncAttrs
	#: AttrString
	#| AttrPair
	#| Align
	: Dereferenceable
	| ReturnAttr
;

ReturnAttr -> ReturnAttr
	: 'inreg'
	| 'noalias'
	| 'nonnull'
	| 'signext'
	| 'zeroext'
;

Section -> Section
	: 'section' Name=StringLit
;

# ref: ParseScope
#
#   ::= syncscope("singlethread" | "<target scope>")?

SyncScope -> SyncScope
	: 'syncscope' '(' Scope=StringLit ')'
;

# ref: ParseOptionalThreadLocal
#
#   := empty
#   := 'thread_local'
#   := 'thread_local' '(' tlsmodel ')'

ThreadLocal -> ThreadLocal
	: 'thread_local'
	| 'thread_local' '(' Model=TLSModel ')'
;

# ref: ParseTLSModel
#
#   := 'localdynamic'
#   := 'initialexec'
#   := 'localexec'

TLSModel -> TLSModel
	: 'initialexec'
	| 'localdynamic'
	| 'localexec'
;

TypeConst -> TypeConst
	: Typ=FirstClassType Val=Constant
;

TypeValue -> TypeValue
	: Typ=FirstClassType Val=Value
;

# ref: ParseOptionalUnnamedAddr

UnnamedAddr -> UnnamedAddr
	: 'local_unnamed_addr'
	| 'unnamed_addr'
;

%interface UnwindTarget;

UnwindTarget -> UnwindTarget
	: UnwindToCaller
	| Label
;

UnwindToCaller -> UnwindToCaller
	: 'to' 'caller'
;

# https://llvm.org/docs/LangRef.html#visibility-styles

# ref: ParseOptionalVisibility
#
#   ::= empty
#   ::= 'default'
#   ::= 'hidden'
#   ::= 'protected'

Visibility -> Visibility
	: 'default'
	| 'hidden'
	| 'protected'
;

Volatile -> Volatile
	: 'volatile'
;
