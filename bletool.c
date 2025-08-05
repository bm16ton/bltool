/**
 * BLE advertise and scan tool
 *  t-kubo @ Zettant Inc.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <bluetooth.h>
#include <hci.h>
#include <hci_lib.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#define DEVICE_NAME   "hci0"
#define DEFAULT_ADV_HEADER "1F"
#define MAX_PKT_SIZE 32

int debugon = 0;
char hint[] = {"hci0"};
static struct hci_filter ofilter;
static volatile int signal_received = 0;
static uint16_t ble_min_interval = 0x100;
static uint16_t ble_max_interval = 0x100;
int pubmacon = 0x00;
char pubmac[] = {"000000000000"};
int advtype = 0x02;
int puborran = 0x01;  //00 for pub
int ownpuborran = 0x01;
int peermap = 0x07;
int filtpol = 0x00;
uint8_t cls[3];
char name[249];
int dev_id;

static int open_device(char *dev_name);

static void sigint_handler(int sig) {
    signal_received = sig;
}

static void hex_dump(char *pref, unsigned char *buf, int len)
{
    printf("%s", pref);
    for (int i = 0; i < len; i++)
        printf("%2.2X", buf[i]);
    printf("  ");

    for (int i = 0; i < len; i++)
        printf("%c", (buf[i] < 0x20 || buf[i] > 0x7e) ? '.' : buf[i]);
    printf("\n");
}

static void cmd_up(int ctl, int hdev, char *opt)
{
	/* Start HCI device */
	if (ioctl(ctl, HCIDEVUP, hdev) < 0) {
		if (errno == EALREADY)
			return;
		fprintf(stderr, "Can't init device hci%d: %s (%d)\n",
						hdev, strerror(errno), errno);
		exit(1);
	}
}

static void cmd_down(int ctl, int hdev, char *opt)
{
	/* Stop HCI device */
	if (ioctl(ctl, HCIDEVDOWN, hdev) < 0) {
		fprintf(stderr, "Can't down device hci%d: %s (%d)\n",
						hdev, strerror(errno), errno);
		exit(1);
	}
}

static void cmd_reset(int ctl, int hdev)
{
	/* Reset HCI device */
#if 0
	if (ioctl(ctl, HCIDEVRESET, hdev) < 0 ){
		fprintf(stderr, "Reset failed for device hci%d: %s (%d)\n",
						hdev, strerror(errno), errno);
		exit(1);
	}
#endif
	cmd_down(ctl, hdev, "down");
	cmd_up(ctl, hdev, "up");
}

/*
int hci_read_class_save(int dd, uint8_t *cls, int to)
{
	read_class_of_dev_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_CLASS_OF_DEV;
	rq.rparam = &rp;
	rq.rlen   = READ_CLASS_OF_DEV_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	memcpy(cls, rp.dev_class, 3);
	return 0;
}
*/
void ctrl_command(uint8_t ogf, uint16_t ocf, char *data) {
    unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr = buf, tmp[2];
    struct hci_filter flt;
    int i, len, dd;

    dd = open_device(hint);
    len = (int)(strlen(data)/2);
    
    for (i=0; i<len; i++) {
        memcpy(tmp, &data[i*2], 2);
        *ptr++ = (uint8_t) strtol((const char *)tmp, NULL, 16);
    }

	if (debugon == 1) {
    printf("data = %s \n", data);
	}
	
    hci_filter_clear(&flt);
    hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
    hci_filter_all_events(&flt);
    if (setsockopt(dd, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
        hci_close_dev(dd);
        perror("HCI filter setup failed");
        exit(EXIT_FAILURE);
    }
    
	if (debugon == 1) {
    	printf("buf ctr cmd %s\n", buf);
    	printf("sent %02x%02x%02x%02x%s\n", dd, ogf, ocf, len, buf);
    	printf("sent int %d%d%d%d\n", dd, ogf, ocf, len);
	}
	
    if (hci_send_cmd(dd, ogf, ocf, len, buf) < 0) {
        hci_close_dev(dd);
        perror("Send failed");
        exit(EXIT_FAILURE);
    }
    hci_close_dev(dd);
}
/*
int hci_write_class_restore(int dd, int to)
{
	write_class_of_dev_cp cp;
	struct hci_request rq;
	char poo = {'\0'};
    ctrl_command(0x03, 0x0003, &poo);
    if (debugon == 1) {
		printf("\tClass: 0x%02x%02x%02x\n", cls[2], cls[1], cls[0]);
	}

	if (hci_write_local_name(dd, name, 2000) < 0) {
		fprintf(stderr, "Can't change local name on hci%d: %s (%d)\n",
					dev_id, strerror(errno), errno);
		exit(1);
	}

	memset(&rq, 0, sizeof(rq));
	cp.dev_class[0] = cls[0]; // cls[2];
	cp.dev_class[1] = cls[1]; // cls[1];
	cp.dev_class[2] = cls[2]; //cls[0];
	
	if (debugon == 1) {
		printf("dev_class 0x%02x%02x%02x\n", cp.dev_class[0], cp.dev_class[1], cp.dev_class[2]);
	}
	
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_CLASS_OF_DEV;
	rq.cparam = &cp;
	rq.clen   = WRITE_CLASS_OF_DEV_CP_SIZE;
	return hci_send_req(dd, &rq, to);
}

static void save_class(char *dev_name)
{
    dev_id = hci_devid(dev_name);
    if (dev_id < 0)
        dev_id = hci_get_route(NULL);

    int dd = hci_open_dev(dev_id);
    if (dd < 0) {
        perror("Could not open device");
        exit(1);
    }
    
	if (hci_read_class_save(dd, cls, 1000) < 0) {
		printf("Can't read class of device on hci%d: %s (%d)\n",
					dev_id, strerror(errno), errno);
		exit(1);
	}

		if (hci_read_local_name(dd, sizeof(name), name, 1000) < 0) {
			fprintf(stderr, "Can't read local name on hci%d: %s (%d)\n",
						dev_id, strerror(errno), errno);
			exit(1);
		}

	printf("local name = %s\n", name);

		for (int i = 0; i < 248 && name[i]; i++) {
			if ((unsigned char) name[i] < 32 || name[i] == 127)
				name[i] = '.';
		}

		name[248] = '\0';

	if (debugon == 1) {
		printf("\tClass: 0x%02x%02x%02x\n", cls[2], cls[1], cls[0]);
	}
	
	hci_close_dev(dd);
}

static void restore_class(char *dev_name) {
    dev_id = hci_devid(dev_name);
    if (dev_id < 0)
        dev_id = hci_get_route(NULL);

    int dd = hci_open_dev(dev_id);
    if (dd < 0) {
        perror("Could not open device");
        exit(1);
    }

	if (debugon == 1) {
		printf("\tClass: 0x%02x%02x%02x\n", cls[2], cls[1], cls[0]);
	}
	
	if (hci_write_class_restore(dd, 2000) < 0) {
		fprintf(stderr, "Can't write local class of device on hci%d: %s (%d)\n",
					dd, strerror(errno), errno);
		exit(1);
	}
	
	hci_close_dev(dd);
}
*/
static int open_device(char *dev_name)
{
    dev_id = hci_devid(dev_name);
    if (dev_id < 0)
        dev_id = hci_get_route(NULL);

    int dd = hci_open_dev(dev_id);
    if (dd < 0) {
        perror("Could not open device");
        exit(1);
    }
    
    return dd;
}

void configure(uint16_t min_interval, uint16_t max_interval)
{
   char data[MAX_PKT_SIZE];

    if(pubmacon == 0) {
    sprintf(data, "%04X%04X%02x%02x%02x000000000000%02x00", htons(min_interval), htons(max_interval), advtype, ownpuborran, puborran, peermap);
    } else if (pubmacon == 1) {
    sprintf(data, "%04X%04X%02x%02x%02x%s%02x00", htons(min_interval), htons(max_interval), advtype, ownpuborran, puborran, pubmac, peermap);
    }
   if (debugon == 1) {
	   printf("conf data = %s\n", data);
	   ctrl_command(0x08, 0x000a, "00");
	}
	
    ctrl_command(0x08, 0x0006, data);
}

void advertise_on(bool on)
{
    ctrl_command(0x08, 0x000a, on ? "01" : "00");
}

void set_advertisement_data(char *data)
{
    char alldata[64];
	if (debugon == 1) {
	    printf("set adv data = %s \n", data);
	}
	
    sprintf(alldata, "%s%s", DEFAULT_ADV_HEADER, data);
    for (int i = strlen(alldata); i <= 63; i++) {
        alldata[i] = '0'; //a000a0000201003a8be8bdd61c0700"};
    }

    ctrl_command(0x08, 0x0008, alldata);
}

void seteventmask(void) {
	char buff[19];
	sprintf(buff, "0x3dbff807fffbffff");
	ctrl_command(0x03, 0x0001, buff);
}

static u_char recvbuf[HCI_MAX_EVENT_SIZE];

int read_advertise(int dd, uint8_t *data, int datalen)
{
    int len;
    evt_le_meta_event *meta;
    le_advertising_info *info;
    unsigned char *ptr;

    while ((len = read(dd, recvbuf, sizeof(recvbuf))) < 0) {
        if (errno == EINTR && signal_received == SIGINT) {
            return 0;
        }

        if (errno == EAGAIN || errno == EINTR)
            continue;
    }

    ptr = recvbuf + (1 + HCI_EVENT_HDR_SIZE);
    len -= (1 + HCI_EVENT_HDR_SIZE);
    meta = (void *) ptr;

    info = (le_advertising_info *) (meta->data + 1);
    memcpy(data, info->data, datalen);
    return len;
}

int print_advertising_devices(int dd) {
    struct sigaction sa;
   	struct hci_version ver;
    unsigned char dat[MAX_PKT_SIZE];

    if (hci_read_local_version(dd, &ver, 1000) < 0) {
		fprintf(stderr, "Can't read version info for hci%d: %s (%d)\n",
						dd, strerror(errno), errno);
	}

	if (debugon == 1) {
		printf("Manufacturer:   %s (%d)\n",
				bt_compidtostr(ver.manufacturer), ver.manufacturer);
	}
	
		printf("Manufacturer:   %s (%d)\n",
				bt_compidtostr(ver.manufacturer), ver.manufacturer);

    if(ver.manufacturer == 2) {
		printf("Entering intel seteventmask\n");
    	seteventmask();
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_NOCLDSTOP;
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    while (1) {
        if (read_advertise(dd, dat, MAX_PKT_SIZE) == 0) break;
        hex_dump("", dat, MAX_PKT_SIZE);
    }
    return 0;
}


void lescan_close(int dd)
{
    uint8_t filter_dup = 0;
    if (dd == -1) {
        dd = open_device(hint);
    } else {
        setsockopt(dd, SOL_HCI, HCI_FILTER, &ofilter, sizeof(ofilter));
    }
    int err = hci_le_set_scan_enable(dd, 0x00, filter_dup, 1000);
    if (err < 0) {
        perror("Disable scan failed");
        exit(1);
    }
    hci_close_dev(dd);
    printf("scan stopped, device closed\n"); 
}

int lescan_setup() {
    int err, dd;
    uint8_t own_type = 0x00;
    uint8_t scan_type = 0x00; // passive
    uint8_t filter_policy = 0x00;
    uint16_t interval = htobs(0x0010);
    uint16_t window = htobs(0x0010);
    uint8_t filter_dup = 0;

    dd = open_device(hint);

    err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
                                     own_type, filter_policy, 1000);
    if (err < 0) {
        lescan_close(-1);
        perror("Set scan parameters failed");
        exit(1);
    }

    err = hci_le_set_scan_enable(dd, 0x01, filter_dup, 1000);
    if (err < 0) {
        hci_close_dev(dd);
        perror("Enable scan failed");
        exit(1);
    }
    
    struct hci_filter nf;
    socklen_t olen;

    olen = sizeof(ofilter);
    if (getsockopt(dd, SOL_HCI, HCI_FILTER, &ofilter, &olen) < 0) {
        hci_close_dev(dd);
        printf("Could not get socket options\n");
        return -1;
    }

    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
    hci_filter_set_event(EVT_LE_META_EVENT, &nf);

    if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
        printf("Could not set socket options\n");
        return -1;
    }

    return dd;
}


static void usage(void)
{
    printf("Usage: bletool <-r | -s> [options...]\n");
    printf("Options:\n"
           "\t-r, --read               Receive mode\n"
           "\t-s, --send=HEX_STRING    Send advertisements\n"
           "\t-h, --help               Display help\n"
           "\t-i, --interface          Select interface\n"
           "\t-t, --type               set advertisement type single digit int\n"
           "\t-p, --ownpublic          1 for own mac random, 0 for public \n"
           "\t-P, --targetpublic       1 for target mac random, 0 for public, requires mac \n"
           "\t-a, --mac                public mac address to target, no colens,\n"
           "\n"
           "Send (-s) advertisement options:\n"
           "\t-m, --min_interval=MS    Minimum interval between adverts in ms (default: 32)\n"
           "\t-M, --max_interval=MS    Maximum interval between adverts in ms (default: 64)\n"
          );
}

static struct option main_options[] = {
    { "help",         no_argument,       0, 'h' },
    { "read",	        no_argument,     0, 'r' },
    { "send",         required_argument, 0, 's' },
    { "interface",    required_argument, 0, 'i' },
    { "type",         required_argument, 0, 't' },
    { "ownpublic",    required_argument, 0, 'p' },
    { "targetpublic", required_argument, 0, 'P' },
    { "mac",          required_argument, 0, 'a' },
    { "min_interval", required_argument, 0, 'm' },
    { "max_interval", required_argument, 0, 'M' },
    { 0,              no_argument,       0,  0  }
};

int main(int argc, char **argv) {
    int option_index = 0, mode = 0, opt;
    char *send_data;
    char *hint2;
    char *mac2;
    
    while ((opt = getopt_long(argc, argv, "r+s:i:t:p:P:a:m:M:h", main_options, &option_index)) != -1) {
        switch (opt) {
        case 'r':
            mode = 1; // receive mode
            break;

        case 's':
            mode = 2;
            send_data = optarg;
            break;

        case 'm':
            ble_min_interval = atoi(optarg);
            break;

        case 'M':
            ble_max_interval = atoi(optarg);
            break;

        case 'i':
            hint2 = optarg;
            for (int p = 0; p < 4; p++) {
            hint[p] = hint2[p];
            }
            break;
            
        case 't':
            advtype = atoi(optarg);
            break;
            
        case 'p':
            ownpuborran = atoi(optarg);
            break;
              
        case 'P':
            puborran = atoi(optarg);
            if(puborran == 0) {
                pubmacon = 1;
            } else {
                pubmacon = 0;
            }
            break;
        
        case 'a':
            mac2 = optarg;
            for (int p = 0; p < 12; p++) {
            pubmac[p] = mac2[p];
            }
            break;
                      
        case 'h':
        default:
            mode = 0;
        }
    }
    
    if (debugon == 1) {
    	printf("ble_min_interval: %d\n", ble_min_interval);
    	printf("ble_max_interval: %d\n", ble_max_interval);
	}
	
    if (mode == 0) {
        usage();
        exit(0);
    } 

    char poo = {'\0'};
//    save_class(hint);
    ctrl_command(0x03, 0x0003, &poo);

   if (mode == 1) {
        int dd = lescan_setup();
        print_advertising_devices(dd);
        lescan_close(dd);
    } else if (mode == 2) {
        configure(ble_min_interval, ble_max_interval);
        set_advertisement_data(send_data);
        advertise_on(true);
        sleep(1);
        advertise_on(false);
    } else {
        printf("ERROR: we shouldn't be here\n");
        exit(1);
    }
	int ctl;
	   ctrl_command(0x03, 0x0003, &poo);
	if ((ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
		perror("Can't open HCI socket.");
		exit(1);
	}
	cmd_reset(ctl, dev_id);
	close(ctl);
	printf("Device Reset\n");
}
