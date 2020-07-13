BIN=$(BIN)
OUT=$(OUT)

all:
	mkdir $(OUT)
	python add_section.py $(BIN) $(OUT)/add_section
	python replace_text.py $(BIN) $(OUT)/replace_text
	python unstrip.py $(BIN) $(OUT)/unstrip
	python nothing.py $(BIN) $(OUT)/nothing

	chmod +x $(OUT)/*

clean:
	rm -rf ./$(OUT)
