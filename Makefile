SOURCE_FILES=src/mdns_message.cc src/mdns_message_header.cc \
	src/mdns_message_question.cc src/mdns_message_rr.cc \
	src/mnet.cc
TEST_SOURCE_FILES= test/test_mdns_message.cc test/gtest_main.cc \
	test/libgtest.a

5ycast: ${SOURCE_FILES} src/main.cc
	g++ -Wall -Werror -g -std=c++11 -Iinclude -o 5ycast \
	${SOURCE_FILES} src/main.cc

tests: ${SOURCE_FILES} ${TEST_SOURCE_FILES}
	g++ -Wall -Werror -g -std=c++11 -pthread -Iinclude \
	-I../googletest/googletest/include/ -o test_dns_message \
	${SOURCE_FILES} ${TEST_SOURCE_FILES}

.PHONY: tests
