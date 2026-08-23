# Build: make            (visible mode, rmmod-able)
#        make hidden     (also unlinks the module; needs a reboot to remove)
obj-m += kdetect_hooktest.o
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

hidden:
	$(MAKE) -C $(KDIR) M=$(PWD) ccflags-y="-DKDETECT_HIDDEN" modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
