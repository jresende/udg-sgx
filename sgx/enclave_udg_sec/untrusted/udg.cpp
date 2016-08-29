#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>

# define MAX_PATH FILENAME_MAX


#include <sgx_urts.h>
#include <sgx_status.h>
#include <iostream>
#include <string>
#include <vector>
#include "udg.h"

#include "udg_sec_u.h"



/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    /* Step 1: retrive the launch token saved by last transaction */

    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
//    printf("token_path: %s\n", token_path);
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(UDG_SEC_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);

    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);

        return -1;
    }

    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);

    return 0;
}

/* OCall functions */
void ocall_udg_sec_sample(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

enum class Action {
	ERROR,
	HELP,
	PARSE,
	VERIFY,
	GENERATE_EPOCH,
	SIZE_EPOCH,
	READ_EPOCH,
	PROCESS,
	TEST
};

Action parse_args(int argc, const char* argv[]) {
	if (argc < 2) {
		return Action::ERROR;
	}

	std::string first_arg(argv[1]);

	if (first_arg.compare("help") == 0) {
		return Action::HELP;
	}

	if (first_arg.compare("parse") == 0) {
		if (argc < 3) {
			std::cerr << "parse switch requires a block (RLP-encoded, hexadecimal text) to be passed in."
					<< std::endl;
			return Action::ERROR;
		}
		return Action::PARSE;
	}

	if (first_arg.compare("process") == 0) {
		if (argc < 4) {
			std::cerr << "process switch requires a block and proof (RLP-encoded lists) to be passed in."
					<< std::endl;
			return Action::ERROR;
		}
		return Action::PROCESS;
	}

	if (first_arg.compare("verify") == 0) {
		if (argc < 3) {
			std::cerr << "verify switch requires a block (RLP-encoded, hexadecimal text) to be passed in."
					<< std::endl;
			return Action::ERROR;
		}
		return Action::VERIFY;
	}

	if (first_arg.compare("test") == 0) {
		return Action::TEST;
	}

	if (first_arg.compare("generate") == 0) {
		return Action::GENERATE_EPOCH;
	}

	if (first_arg.compare("epoch") == 0) {
		if (std::string(argv[2]).compare("read") == 0) {
			return Action::READ_EPOCH;
		} else if (std::string(argv[2]).compare("size") == 0) {
			return Action::SIZE_EPOCH;
		}
	}

	return Action::ERROR;
}

int* parse_generate_args(int argc, const char **argv) {
	auto out = new int[argc];
	for (int i = 0; i < argc; i++) {
//		std::cout << strtol(argv[i], nullptr, 10);
		out[i] = (strtol(argv[i], nullptr, 10));
	}
	return out;
}

void print_help() {
	std::cout << "Usage: udg switch args...\n"
			<< "    Switches:\n"
			<< "        help        print this help message, then exit.\n"
			<< "        parse       parse the rlp representation of a\n"
			   "                    block, print out a plain text representation.\n"
			<< "        verify      parse and verify the contents of a block.\n"
			<< "        test        run the tests built into the executable.\n"
			<< "        generate    generate the specified epochs (given as\n"
			<< "                    epoch numbers, starting from 0)\n"
			<< "        epoch [switch]\n"
			<< "            read    reads and outputs the hash of an epoch, without\n"
			<< "                    creating any new files.\n"
			<< "            size    outputs the size of the cache for the ethash of\n"
			<< "                    an epoch.\n"
			<< std::endl;
}

void print_error() {
	std::cerr << "Unrecognized or invalid parameters." << std::endl;
}

void print_failure() {
	std::cerr << "Something went wrong." << std::endl;
}

/* Application entry */
int SGX_CDECL main(int argc, const char *argv[])
{

    /* Changing dir to where the executable is.*/
    char absolutePath [MAX_PATH];
    char *ptr = NULL;

    ptr = realpath(dirname(const_cast<char*>(argv[0])),absolutePath);

    if( chdir(absolutePath) != 0)
    		abort();

    /* Initialize the enclave */
    if(initialize_enclave() < 0){

        return -1; 
    }
 
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int ecall_return = 0;

    auto act = parse_args(argc, argv);
    int* inp;

    switch (act) {
		case Action::TEST: {

				ret = ecall_test(global_eid, &ecall_return);
				if (ret != SGX_SUCCESS || ecall_return != 0) {
					print_failure();
					return ecall_return;
				}
			}
			break;

		case Action::ERROR:
			print_error();
			/* no break */
		case Action::HELP:
			print_help();
			break;

		case Action::VERIFY:
			ret = ecall_udg_verify(global_eid, &ecall_return, argv[2]);
			if (ret != SGX_SUCCESS || ecall_return != 0) {
				print_failure();
				return ecall_return;
			}
			break;

    	case Action::PARSE:
    		ret = ecall_udg_parse(global_eid, &ecall_return, argv[2]);
    		if (ret != SGX_SUCCESS || ecall_return != 0) {
    			print_failure();
				return ecall_return;
			}
			break;

    	case Action::GENERATE_EPOCH:
    		inp = parse_generate_args(argc - 2, argv + 2);
    		for (int i = 0; i < argc - 2; i++) {
    			ret = ecall_udg_generate_epoch(global_eid, &ecall_return, inp[i]);
				if (ret != SGX_SUCCESS || ecall_return != 0) {
					print_failure();
					return ecall_return;
				}
    		}

    		delete [] inp;
    		break;

    	case Action::READ_EPOCH:
    		inp = new int;
    		*inp = atoi(argv[3]);
    		ret = ecall_udg_read_epoch(global_eid, &ecall_return, *inp);
			if (ret != SGX_SUCCESS || ecall_return != 0) {
				print_failure();
				return ecall_return;
			}
    		delete inp;
    		break;

    	case Action::SIZE_EPOCH:
			inp = new int;
			*inp = atoi(argv[3]);
			ret = ecall_udg_size_epoch(global_eid, &ecall_return, *inp);
			if (ret != SGX_SUCCESS || ecall_return != 0) {
				print_failure();
				return ecall_return;
			}
			delete inp;
			break;

    	case Action::PROCESS:
    		ret = ecall_udg_process(global_eid, &ecall_return, argv[2], argv[3]);
			if (ret != SGX_SUCCESS || ecall_return != 0) {
				print_failure();
				return ecall_return;
			}
			break;

		default:
			print_error();
			print_help();
			break;

    }

//    if (ecall_return == 0) {
//      printf("Application ran with success\n");
//    }
//    else
//    {
//        printf("Application failed %d \n", ecall_return);
//    }
    
    sgx_destroy_enclave(global_eid);
    
    if (act == Action::ERROR) {
    	return -1;
    } else {
    	return 0;
    }
}
