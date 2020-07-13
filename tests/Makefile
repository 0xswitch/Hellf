BIN=$(BIN)
OUT=$(OUT)

all:
	mkdir -p $(OUT)
	python add_section.py $(BIN) $(OUT)/add_section
	python replace_text.py $(BIN) $(OUT)/replace_text
	python unstrip.py $(BIN) $(OUT)/unstrip
	python nothing.py $(BIN) $(OUT)/nothing

	chmod +x $(OUT)/*

clean:
	rm -rf ./$(OUT)

nothing:
	@mkdir -p $(OUT)
	@python nothing.py $(BIN) $(OUT)/nothing
	$(eval sha_new = $(shell sha256sum $(OUT)/nothing | cut -d " " -f 1))
	$(eval sha_old = $(shell sha256sum $(BIN) | cut -d " " -f 1))
	@if [ $(sha_new) = $(sha_old) ]; then \
		echo "match"; \
	else \
		echo "do not match"; \
	fi
