#include <arpa/inet.h>
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
	char buffer[256];
	int type = udp;
	int sock = 10;

	struct socket_info_t socket_info;
	socket_info.protocol = SOCK_DGRAM;
	socket_info.addr_1.sa_family = AF_INET;
	socket_info.addr4_1.sin_addr.s_addr = INADDR_ANY;
	socket_info.addr4_1.sin_port = ntohs(2000);
	socket_info.addr_2.sa_family = AF_INET;
	socket_info.addr4_2.sin_addr.s_addr = INADDR_ANY;
	socket_info.addr4_2.sin_port = ntohs(5000);

	CU_ASSERT_PTR_NOT_NULL(_loopkb_nmq_generate_filename_for_socket(sock, &socket_info, type, buffer, 256));
	CU_ASSERT_STRING_EQUAL("_loopkb_ipv4.udp.0.0.0.0:2000:0.0.0.0:5000", buffer);

	socket_info.protocol = SOCK_DGRAM;
	socket_info.addr_1.sa_family = AF_INET;
	socket_info.addr4_1.sin_addr.s_addr = inet_addr("127.0.0.2");
	socket_info.addr4_1.sin_port = ntohs(60550);
	socket_info.addr_2.sa_family = AF_INET;
	socket_info.addr4_2.sin_addr.s_addr = inet_addr("192.168.0.1");
	socket_info.addr4_2.sin_port = ntohs(10010);

	CU_ASSERT_PTR_NOT_NULL(_loopkb_nmq_generate_filename_for_socket(sock, &socket_info, type, buffer, 256));
	CU_ASSERT_STRING_EQUAL("_loopkb_ipv4.udp.127.0.0.2:60550:192.168.0.1:10010", buffer);
}

void test_loopkb_nmq_should_offload_ipv4()
{
	size_t ipv4_offloaded_addresses_count = 0;
	struct ipv4_address_mask_t ipv4_offloaded_addresses[4];

	inet_pton(AF_INET, "127.0.0.1", &ipv4_offloaded_addresses[0].ip_addr);
	inet_pton(AF_INET, "255.0.0.0", &ipv4_offloaded_addresses[0].mask);
	++ipv4_offloaded_addresses_count;

	inet_pton(AF_INET, "192.168.0.1", &ipv4_offloaded_addresses[1].ip_addr);
	inet_pton(AF_INET, "255.255.255.255", &ipv4_offloaded_addresses[1].mask);
	++ipv4_offloaded_addresses_count;

	uint32_t ip_addr = INADDR_ANY;
	CU_ASSERT_FALSE(_loopkb_nmq_should_offload_ipv4(ipv4_offloaded_addresses, ipv4_offloaded_addresses_count, ip_addr));

	inet_pton(AF_INET, "127.0.0.1", &ip_addr);
	CU_ASSERT_TRUE(_loopkb_nmq_should_offload_ipv4(ipv4_offloaded_addresses, ipv4_offloaded_addresses_count, ip_addr));

	inet_pton(AF_INET, "127.0.0.2", &ip_addr);
	CU_ASSERT_TRUE(_loopkb_nmq_should_offload_ipv4(ipv4_offloaded_addresses, ipv4_offloaded_addresses_count, ip_addr));

	inet_pton(AF_INET, "128.0.0.2", &ip_addr);
	CU_ASSERT_FALSE(_loopkb_nmq_should_offload_ipv4(ipv4_offloaded_addresses, ipv4_offloaded_addresses_count, ip_addr));

	inet_pton(AF_INET, "192.168.0.1", &ip_addr);
	CU_ASSERT_TRUE(_loopkb_nmq_should_offload_ipv4(ipv4_offloaded_addresses, ipv4_offloaded_addresses_count, ip_addr));
}

int main()
{
	CU_initialize_registry();

	CU_pSuite suite = CU_add_suite("LoopKB", init_suite, clean_suite);
	CU_add_test(suite, "test _loopkb_nmq_generate_filename_for_socket", test_loopkb_nmq_generate_filename_for_socket);
	CU_add_test(suite, "test _loopkb_nmq_should_offload_ipv4", test_loopkb_nmq_should_offload_ipv4);

	CU_basic_run_tests();
	const int retval = CU_get_number_of_failures();
	CU_cleanup_registry();
	return retval;
}
