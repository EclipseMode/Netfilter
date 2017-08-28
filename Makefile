nfqnl_test : nfqnl_test.c
	gcc -o nfqnl_test nfqnl_test.c -lnfnetlink -lnetfilter_queue
