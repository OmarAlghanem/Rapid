# myrapid host/Makefile

ifeq ($(CFG_ARM64_core),y)
    AARCH32 :=
else
    AARCH32 := 32
endif

CPPFLAGS += -I$(TEEC_EXPORT)/include
CPPFLAGS += -I$(TA_DEV_KIT_DIR)/include
CPPFLAGS += -I/usr/local/include
CPPFLAGS += -I/home/rapid/TrustZone/optee_examples/myrapid/ta

LDFLAGS += /home/rapid/TrustZone/optee_client/out/libteec/libteec.a
LDFLAGS += -L/usr/local/lib -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto
LDFLAGS += -lwiringPi

# Remove redundant -lteec here, as we are linking directly to the static library
LDADD +=

CFLAGS += -Wall -g

OBJS = client_robot.o

all: myrapid

myrapid: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJS) myrapid

