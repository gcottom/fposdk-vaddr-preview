CXX ?= c++
CXXFLAGS ?= -std=c++23 -O2 -Wall -Wextra -Wpedantic
LDLIBS += -lz
SOURCES = PluginHeader.cpp PluginGraph.cpp PluginFileScanner.cpp PluginFormID.cpp PluginFormInventory.cpp MappingTable.cpp

.PHONY: test clean
test: preview-tests
	@dir=$$(mktemp -d) && trap 'rm -f -- "$$dir/fixture.esp" "$$dir/bad.esp"; rmdir "$$dir"' EXIT && ./preview-tests "$$dir"

preview-tests: preview-tests.cpp $(SOURCES) $(wildcard *.hpp)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -o $@ preview-tests.cpp $(SOURCES) $(LDLIBS)

clean:
	rm -f preview-tests
