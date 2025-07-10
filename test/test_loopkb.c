#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "loopkb.h" // Your library header
#include "nmq-backend.h" // Your library header

int init_suite()
{
	return 0;
}

int clean_suite()
{
	return 0;
}

void test_loopkb_nmq_generate_filename_for_socket()
{
	int sock = _sys_socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	CU_ASSERT_TRUE(sock >= 0);
	_sys_close(sock);
}

int main()
{
	CU_initialize_registry();

	CU_pSuite suite = CU_add_suite("LoopKB", init_suite, clean_suite);
	CU_add_test(suite, "test _loopkb_nmq_generate_filename_for_socket", test_loopkb_nmq_generate_filename_for_socket);

	CU_basic_run_tests();
	const int retval = CU_get_number_of_failures();
	CU_cleanup_registry();
	return retval;
}
