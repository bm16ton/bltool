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

#include <sys/poll.h>
#include <sys/socket.h>
#include <bluetooth.h>
#include <hci.h>
#include <hci_lib.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include "bletool.h"

#define DEVICE_NAME   "hci0"
#define DEFAULT_ADV_HEADER "1F"
#define MAX_PKT_SIZE 32

int debugon = 0;
char hint[] = {"hci0"};
static struct hci_filter ofilter;
static volatile int signal_received = 0;
static uint16_t ble_min_interval = 0x100;
static uint16_t ble_max_interval = 0x100;
uint16_t ble_scan_interval = 0x0010;
uint16_t ble_scan_window = 0x0010;
uint16_t le_1m_scan_interval = 0x0012;
uint16_t le_1m_scan_window = 0x0012;
uint16_t coded_scan_interval = 0x0036;
uint16_t coded_scan_window = 0x0036;
int pubmacon = 0x00;
char pubmac[] = {"000000000000"};
char rando[] = {"19a4d57769e1"};
int advtype = 0x02;
int puborran = 0x01;  //00 for pub
int ownpuborran = 0x01;
int peermap = 0x07;
int filtpol = 0x00;
uint8_t cls[3];
char name[249];
int dev_id;
int active = 0;
int filtdups = 0;
int showadv = 0;
int die = 0;
unsigned char bdaddrrssi[MAX_PKT_SIZE];
static int open_device(char *dev_name);
int read_advertise(int dd, uint8_t *data, int datalen);
int read_scan(int dd, uint8_t *data, int datalen);
const char* find_label_by_type(unsigned int type_code);

static void sigint_handler(int sig) {
    signal_received = sig;
	die = 1;
}

const char* find_label_by_type(unsigned int type_code) {
    for (int i = 0; i < sizeof(type_labels) / sizeof(type_labels[0]); i++) {
        if (type_labels[i].type_code == type_code) {
            return type_labels[i].label;
        }
    }
    return "UNKNOWN_TYPE";
}

const char* find_comp_by_type(unsigned int compname) {
    for (int i = 0; i < sizeof(comp_labels) / sizeof(comp_labels[0]); i++) {
        if (comp_labels[i].compname == compname) {
            return comp_labels[i].complabel;
        }
    }
    return "UNKNOWN_TYPE";
}

static void hex_dump(char *pref, unsigned char *buf, int len)
{
	if((active == 0) || (showadv == 1)) {
 	   printf("%s", pref);
  	  for (int i = 0; i < len; i++)
  	      printf("%2.2X", buf[i]);
  	  printf("  ");
	}
	if (active == 0) {
    	for (int i = 0; i < len; i++) {
    	    printf("%c", (buf[i] < 0x20 || buf[i] > 0x7e) ? '.' : buf[i]);
		} 
	} 
		if ((buf[1] == 0x09) || (buf[1] == 0x08)) {
			printf(" DevName ");
			for (int i = 0; i < (buf[0] - 1); i++) {
				printf("%c", buf[2 + i]);
			}
			printf(" ");
		}
		if (buf[1] == 0xFF) { 
			char newname[6] = {0x00};
			sprintf(newname, "%X%X", buf[3], buf[2]);
			uint32_t good = strtol(newname, NULL, 16);
	        const char* complabel = find_comp_by_type(good);
			printf(" Chip mkr: \"%s\"", complabel);
			printf(" %04x", good);
		}
	
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

void active_lescan_setup(void) {
//    unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr = buf, tmp[2];
    struct hci_filter flt;
    int dd;
    struct sigaction sa;
    unsigned char dat[MAX_PKT_SIZE];

	char data[MAX_PKT_SIZE];
	char data2[MAX_PKT_SIZE];

    // Allocate memory for inquiry_info structures
//   ii = (inquiry_info*)malloc(max_rsp * sizeof(inquiry_info));
    hci_filter_clear(&flt);
    hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
    hci_filter_all_events(&flt);


	dd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
	if (dd < 0)
		;//	return;
    if (setsockopt(dd, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
        hci_close_dev(dd);
        perror("HCI filter setup failed");
        exit(EXIT_FAILURE);
    }

	// 01=scanon/ 00=filtdups/ 0000=duration / 0000=period
	sprintf(data, "010000000000");
	//02x=size / 00=filtpol / 
	sprintf(data2, "01000501%04x%04x01%04x%04x", htons(le_1m_scan_interval), htons(le_1m_scan_window), htons(coded_scan_interval), htons(coded_scan_window));
	//char onval[] = {'\x01'};

	ctrl_command(0x08, 0x002d, "00");
	//ctrl_command(0x08, 0x002d, onval);  //0x08|0x002d opcode 0x202d
	ctrl_command(0x08, 0x0005, rando);			//le set random addr 0x08|0x0005 opcode 0x2005

	ctrl_command(0x08, 0x0041, data2);		//set extended scan parameters
	ctrl_command(0x08, 0x0042, data);
	//printf("before last ctrl command\n");
	ctrl_command(0x03, 0x001a, "02");


    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_NOCLDSTOP;
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    while (1) {
        if (read_scan(dd, dat, MAX_PKT_SIZE) == 0) break;
        hex_dump("", dat, MAX_PKT_SIZE);
    }
    hci_close_dev(dd);
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
	sprintf(buff, "fffffbff07f8bf3d");
//	sprintf(buff, "3dbff807fffbffff");
	ctrl_command(0x03, 0x0001, buff);
}

static u_char recvbuf[HCI_MAX_EVENT_SIZE];

int read_advertise(int dd, uint8_t *data, int datalen)
{
    int len;
    evt_le_meta_event *meta;
    le_advertising_info *info;
    unsigned char *ptr;
	char name[248] = { 0 };
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

	memset(name, 0, sizeof(name));

    info = (le_advertising_info *) (meta->data + 1);
	char addr[18];
	
    ba2str(&info->bdaddr, addr);
	char newname[7] = {0};
	sprintf(newname, "%c%c%c%c%c%c", addr[0], addr[1], addr[3], addr[4], addr[6], addr[7]);
	uint32_t good = strtol(newname, NULL, 16);
	const char* label = find_label_by_type(good);
    printf("%s, Manufacturer \"%s\" RSSI: %d ", addr, label, (char)info->data[info->length]);
    memcpy(data, info->data, datalen);
    return len;
}

int read_scan(int dd, uint8_t *data, int datalen) {
    inquiry_info *ii = NULL;
    int max_rsp, num_rsp;
    int len, flags;
    int i;
    char addr[19] = { 0 };
    char name[248] = { 0 };

    len = 8; // Length of inquiry in 1.28-second units (8 * 1.28s = 10.24 seconds)
    max_rsp = 255; // Maximum number of responses
    flags = IREQ_CACHE_FLUSH; // Flush the cache before inquiry

    // Allocate memory for inquiry_info structures
    ii = (inquiry_info*)malloc(max_rsp * sizeof(inquiry_info));

    // Perform the HCI inquiry (scan)
    num_rsp = hci_inquiry(dev_id, len, max_rsp, NULL, &ii, flags);

    if (num_rsp < 0) {
        perror("hci_inquiry");
    }

    // Iterate through discovered devices and print their addresses and names
    for (i = 0; i < num_rsp; i++) {
        ba2str(&(ii+i)->bdaddr, addr); // Convert Bluetooth address to string
//		printf("badaddr0 %02x bdaddr1 %02x bdaddr3 %02x\n", addr[0], addr[1], addr[2]);
        memset(name, 0, sizeof(name));
        // Read the remote name of the device
        if (hci_read_remote_name(dd, &(ii+i)->bdaddr, sizeof(name), name, 0) < 0) {
            strcpy(name, "[unknown]");
        }
        printf("%s %s\n", addr, name);
    }

    free(ii);
 //   close(sock);

    return 0;
}


int print_advertising_devices(int dd) {
    struct sigaction sa;
//	if (active == 0) {
   	struct hci_version ver;
//	}
    unsigned char dat[MAX_PKT_SIZE];
//	if (active == 0) {
    if (hci_read_local_version(dd, &ver, 1000) < 0) {
		fprintf(stderr, "Can't read version info for hci%d: %s (%d)\n",
						dd, strerror(errno), errno);
	}

	if (debugon == 1) {
		printf("Manufacturer:   %s (%d)\n",
				bt_compidtostr(ver.manufacturer), ver.manufacturer);
	}
	
//		printf("Manufacturer:   %s (%d)\n",
//				bt_compidtostr(ver.manufacturer), ver.manufacturer);

    if(ver.manufacturer == 2) {
		printf("Found Intel ble\n");
		printf("Entering intel seteventmask\n");
    	seteventmask();
    }
//	}
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_NOCLDSTOP;
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    while (1) {
//        if (errno == EINTR && signal_received == SIGINT) {
//            return 0;
//        }
		if (die == 1){
			return 0;
		}
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

int lescan_setup(void) {
    int err, dd;
	uint8_t scan_type = 0x00;
	
	if (active == 1) {
	scan_type = 0x01;
	}
	
    uint8_t own_type = 0x00;
	if (active == 1) {
		own_type = 0x00;
	} else {
		own_type = 0x00;
	}
 //   uint8_t scan_type = 0x00; // passive
    uint8_t filter_policy = 0x00;
    uint16_t interval = htons(ble_scan_interval);  //htobs(0x0010);
    uint16_t window = htons(ble_scan_window);    //htobs(0x0010);
	uint8_t filter_dup = 0;
	if (filtdups == 0) {
    	filter_dup = 0;
	} else if (filtdups == 1) {
		filter_dup = 1;
	}
    dd = open_device(hint);

	char data[MAX_PKT_SIZE];
	char data2[MAX_PKT_SIZE];
	if(active == 1) {
	sprintf(data, "010000000000");  //enable extended scan
// 01=ext-scan-enable the rest filt dups duration and period in unknown order 
	sprintf(data2, "01000501%04x%04x01%04x%04x", htons(le_1m_scan_interval), htons(le_1m_scan_window), htons(coded_scan_interval), htons(coded_scan_window)); //set extended scan options
// 01=own addr type(random) 00=filt policy(all) 05=phys 01=type(active) 0x0000=1m_scan_interval 0x0000=1m_scan_window 01=type(active) 0x0000=coded_interval 0x0000=coded_window 
//
	}


//	if (active == 0) {
    err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
                                     own_type, filter_policy, 1000);
    if (err < 0) {
	        lescan_close(-1);
	        perror("Set scan parameters failed");
	        exit(1);
	    }
//	}
	

	if (active == 1) {
//		ctrl_command(0x08, 0x0005, rando);
		ctrl_command(0x08, 0x0041, data2);		//set extended scan parameters
		if (filtdups == 1) {
			ctrl_command(0x08, 0x000c, "0101");
		} else {
			ctrl_command(0x08, 0x000c, "0100");
		}
		ctrl_command(0x08, 0x0042, data);		//enable extended scan
	}


	if (active == 0) {
    	err = hci_le_set_scan_enable(dd, 0x01, filter_dup, 1000);
    	if (err < 0) {
        	hci_close_dev(dd);
        	perror("Enable scan failed");
        	exit(1);
    	}
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
    printf("Usage: bletool <-r/R | -s> [options...]\n");
    printf("Options:\n"
		   "	General Options:\n											\n"
           "		\t-h, --help						Display help\n"
           "		\t-i, --interface					Select interface\n"
		   "		\t-D, --debug						Enable tons of debug msgs\n"
		   "	Shared Options:												\n"
           "		\t-p, --ownpublic					1 for own mac random, 0 for public \n"
           "		\t-P, --targetpublic				1 for target mac random, 0 for public, requires mac \n"
           "		\t-a, --mac							public mac address to target, no colens\n"
           "	Send (-s) advertisement options:\n"
           "		\t-s, --send=HEX_STRING				Send advertisements\n"
           "		\t-t, --type						set advertisement type single digit int\n"
           "		\t-m, --min_interval=MS				TX Minimum interval between adverts in ms (default: 32)\n"
           "		\t-M, --max_interval=MS				TX Maximum interval between adverts in ms (default: 64)\n"
		   "	Receive (-r) options:\n"
           "		\t-r, --read						Receive in passive mode\n"
		   "		\t-R, --Read						Receive in active LE mode\n"
		   "		\t-A  --showadvert					Always show advertising data even in active\n"
		   "		\t-f, --filter_dups					Enable filtering duplicates\n"
           "		\t-I, --scan_rec_interval=HEX		Scanning interval value wo 0x prefix (default: 0x0010)\n"
           "		\t-W, --scan_rec_window=HEX			Scanning interval value wo 0x prefix (default: 0x0010)\n"
           "		\t-l, --le_1m_rec_interval=HEX		le 1m active scan interval, wo 0x prefix (default: 0x0036)\n"
           "		\t-L, --le_1m_rec_window=HEX 		le 1m active scan window, wo 0x prefix (default: 0x0036)\n"
           "		\t-c, --le_coded_rec_interval=HEX	le coded active scan interval, wo 0x prefix (default: 0x0036)\n"
           "		\t-C, --le_coded_rec_window=HEX 	le coded active scan window, wo 0x prefix (default: 0x0036)\n"
			"\n\n"
          );
}

static struct option main_options[] = {
    { "help",         no_argument,       0, 'h' },
    { "read",	      no_argument,       0, 'r' },
	{ "Read",		  no_argument,       0, 'R' },
    { "debug",        no_argument, 		 0, 'D' },
    { "send",         required_argument, 0, 's' },
    { "interface",    required_argument, 0, 'i' },
    { "type",         required_argument, 0, 't' },
    { "ownpublic",    required_argument, 0, 'p' },
    { "targetpublic", required_argument, 0, 'P' },
    { "mac",          required_argument, 0, 'a' },
    { "min_interval", required_argument, 0, 'm' },
    { "max_interval", required_argument, 0, 'M' },
    { "scan_rec_interval", required_argument, 0, 'I' },
    { "scan_rec_window", required_argument, 0, 'W' },
    { "le_coded_rec_interval", required_argument, 0, 'c' },
    { "le_coded_rec_window", required_argument, 0, 'C' },
    { "le_1m_rec_interval", required_argument, 0, 'l' },
    { "le_1m_rec_window", required_argument, 0, 'L' },
	{ "filter_dups", no_argument, 0, 'f' },
	{ "showadvert", no_argument, 0, 'A' },
    { 0,              no_argument,       0,  0  }
};

int main(int argc, char **argv) {
    int option_index = 0, mode = 0, opt;
    char *send_data;
    char *hint2;
    char *mac2;
    
    while ((opt = getopt_long(argc, argv, "r+cCAlfLRDs:i:t:p:P:a:m:M:I:W:h", main_options, &option_index)) != -1) {
        switch (opt) {
        case 'r':
            mode = 1; // receive mode passive
            break;

        case 's':
            mode = 2;
            send_data = optarg;
            break;

        case 'R':
            mode = 3; // receive mode active
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

		case 'A':
			showadv = 1;
			break;

		case 'f':
			filtdups = 1;
			break;

        case 'D':
            debugon = 1;
            break;

        case 'I':
            le_1m_scan_interval = atoi(optarg);
			printf("scan interval = %02x\n", atoi(optarg));
            break;

        case 'W':
            le_1m_scan_window = atoi(optarg);
			printf("scan window = %02x\n", atoi(optarg));
            break;

        case 'h':
        default:
            mode = 0;
        }
    }
    
    if ((debugon == 1) && (mode == 2)) {
    	printf("ble_min_interval: %d\n", ble_min_interval);
    	printf("ble_max_interval: %d\n", ble_max_interval);
	}
	
    if (mode == 0) {
        usage();
        exit(0);
    } 

    char poo = {'\0'};
    ctrl_command(0x03, 0x0003, &poo);

   if (mode == 1) {
		active = 0;
        int dd = lescan_setup();
        print_advertising_devices(dd);
        lescan_close(dd);
    } else if (mode == 2) {
        configure(ble_min_interval, ble_max_interval);
        set_advertisement_data(send_data);
        advertise_on(true);
        sleep(1);
        advertise_on(false);
    } else if (mode == 3) {
		active = 1;
		int dd = lescan_setup();
		print_advertising_devices(dd);
		lescan_close(dd);
//		active_lescan_setup();
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
