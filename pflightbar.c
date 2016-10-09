/*
 * Copyright (c) 2016 joshua stein <jcs@jcs.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pcap.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#ifdef __amd64__
#include <machine/chromeecvar.h>
#else
#error "this requires amd64"
#endif

int chromeec;
time_t last_flash;

void chromeec_set_seq(int);
void chromeec_load_program(void);
void have_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

int
main(int argc, char **argv)
{
	pcap_handler phandler = have_packet;
	pcap_t *hpcap;
	struct passwd *pw;
	char errbuf[PCAP_ERRBUF_SIZE];

	if ((pw = getpwnam("nobody")) == NULL)
		errx(1, "nobody?");
	endpwent();

	if ((hpcap = pcap_open_live("pflog0", 1, 1, 500, errbuf)) == NULL)
		errx(1, "failed pcap_open_live(pflog0): %s", errbuf);

	if (pcap_datalink(hpcap) != DLT_PFLOG)
		errx(1, "invalid datalink type");

	if (ioctl(pcap_fileno(hpcap), BIOCLOCK) < 0)
		err(1, "BIOCLOCK");

	if ((chromeec = open("/dev/chromeec", O_RDWR)) == -1)
		err(1, "open /dev/chromeec");

	if (chroot("/var/empty") != 0 || chdir("/") != 0)
		err(1, "suk");
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		err(1, "setresgid/setresuid");

	chromeec_load_program();
	last_flash = time(NULL);

	while (1) {
		if (pcap_dispatch(hpcap, 1, phandler, NULL) < 0)
			errx(1, "%s", pcap_geterr(hpcap));
	}

	return (0);
}

void chromeec_set_seq(int param)
{
	if (ioctl(chromeec, CHROMEEC_IOC_LIGHTBAR_SET_SEQ, &param) < 0)
		err(1, "ioctl");
}

void chromeec_load_program(void)
{
	struct chromeec_lightbar_program p = { 0 };
	int i = 0;

	/* red */
	p.data[i++] = CHROMEEC_LIGHTBAR_OPCODE_SET_COLOR_SINGLE;
	p.data[i++] = 0xf4;
	p.data[i++] = 0xff;

	/* ramp as fast as possible */
	p.data[i++] = CHROMEEC_LIGHTBAR_OPCODE_SET_RAMP_DELAY;
	p.data[i++] = 0x00;
	p.data[i++] = 0x00;
	p.data[i++] = 0x00;
	p.data[i++] = 0x01;

	/* cycle once and end */
	p.data[i++] = CHROMEEC_LIGHTBAR_OPCODE_ON;
	p.data[i++] = CHROMEEC_LIGHTBAR_OPCODE_CYCLE_ONCE;
	p.data[i++] = CHROMEEC_LIGHTBAR_OPCODE_OFF;
	p.data[i++] = CHROMEEC_LIGHTBAR_OPCODE_HALT;

	p.size = i;

	/* if the ec happens to be in SEQ_STOP it won't respond, so force it
	 * back into s0 */
	chromeec_set_seq(CHROMEEC_LIGHTBAR_SEQ_S0);

	if (ioctl(chromeec, CHROMEEC_IOC_LIGHTBAR_SET_PROGRAM, &p) < 0)
		err(1, "ioctl");
}

void
have_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
	if (time(NULL) - last_flash <= 0)
		return;

	last_flash = time(NULL);

	chromeec_set_seq(CHROMEEC_LIGHTBAR_SEQ_PROGRAM);
}
