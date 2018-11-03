* add `SummaryDef` to grammar (ref: [ParseSummaryEntry](https://github.com/llvm-mirror/llvm/blob/d0abf8be7d16d63c025fb9709404ee865d2acc1a/lib/AsmParser/LLParser.cpp#L801)).

```c
SummaryDef
   : SummaryID '=' SummaryEntry
;
```
