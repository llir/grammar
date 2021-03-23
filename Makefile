TM_DIR=./tools/textmapper

all: gen

gen: ll.tm
	@${TM_DIR}/tm-tool/libs/textmapper.sh $<
	@find . -type f -name '*.go' | xargs -I '{}' goimports -w '{}' > /dev/null
	@go install ./... > /dev/null

clean:
	$(RM) -v listener.go lexer.go lexer_tables.go parser.go parser_tables.go token.go
	$(RM) -rf -v ast/
	$(RM) -rf -v selector/

.PHONY: all gen clean
