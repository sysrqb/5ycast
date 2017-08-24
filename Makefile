tests:
	g++ -Werror -g -std=c++11 -pthread -Iinclude \
	-I../googletest/googletest/include/ -o test_dns_message \
	src/mdns_message.cc src/mdns_message_header.cc \
	src/mdns_message_question.cc src/mdns_message_rr.cc \
	test/test_mdns_message.cc test/gtest_main.cc test/libgtest.a

.PHONY: tests
