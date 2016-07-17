######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2 -DNDEBUG
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto

Udg_sec_Cpp_Files := $(shell find trusted/ -type f -name '*.cpp')
Udg_sec_C_Files := $(shell find trusted/ -type f -name '*.c')
Udg_sec_Include_Paths := -IInclude -Itrusted -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport


Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Udg_sec_Include_Paths) -fno-builtin-printf -I. -DINTEL_SGX_ENV
Udg_sec_C_Flags := $(Flags_Just_For_C) $(Common_C_Cpp_Flags)
Udg_sec_Cpp_Flags :=  $(Common_C_Cpp_Flags) -std=c++11 -nostdinc++ -fno-builtin-printf -I.

Udg_sec_Cpp_Flags := $(Udg_sec_Cpp_Flags)  -fno-builtin-printf

Udg_sec_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=trusted/udg_sec.lds

Udg_sec_Cpp_Objects := $(Udg_sec_Cpp_Files:.cpp=.o)
Udg_sec_C_Objects := $(Udg_sec_C_Files:.c=.o)

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: udg_sec.so
	@echo "Build enclave udg_sec.so  [$(Build_Mode)|$(SGX_ARCH)] success!"
	@echo
	@echo "*********************************************************************************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the udg_sec.so first using Two Step Sign mechanism before you run the app to launch and access the enclave."
	@echo "*********************************************************************************************************************************************************"
	@echo 


else
all: udg_sec.signed.so
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/app
	@echo "RUN  =>  app [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif


######## udg_sec Objects ########

trusted/udg_sec_t.c: $(SGX_EDGER8R) ./trusted/udg_sec.edl
	@cd ./trusted && $(SGX_EDGER8R) --trusted ../trusted/udg_sec.edl --search-path ../trusted --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

trusted/udg_sec_t.o: ./trusted/udg_sec_t.c
	@$(CC) $(Udg_sec_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

trusted/%.o: trusted/%.cpp
	@$(CXX) $(Udg_sec_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

trusted/%.o: trusted/%.c
	@$(CC) $(Udg_sec_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

udg_sec.so: trusted/udg_sec_t.o $(Udg_sec_Cpp_Objects) $(Udg_sec_C_Objects)
	@$(CXX) $^ -o $@ $(Udg_sec_Link_Flags)
	@echo "LINK =>  $@"

udg_sec.signed.so: udg_sec.so
	@$(SGX_ENCLAVE_SIGNER) sign -key trusted/udg_sec_private.pem -enclave udg_sec.so -out $@ -config trusted/udg_sec.config.xml
	@echo "SIGN =>  $@"
clean:
	@rm -f udg_sec.* trusted/udg_sec_t.* $(Udg_sec_Cpp_Objects) $(Udg_sec_C_Objects)
