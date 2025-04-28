# myrapid ta/Makefile

BINARY := myrapid_ta #This will instruct OP-TEE to build myrapid_ta as a binary trusted application

include /home/rapid/TrustZone/optee_os/ta/mk/ta_dev_kit.mk
include /home/rapid/TrustZone/optee_os/ta/link.mk



# TA UUID (make sure same in .h and Makefile)
ta_uuid := d599cac9-1c19-474e-a5ed-2fb5d8430362

# The name of the TA binary
$(eval $(call ta_bin, myrapid))

