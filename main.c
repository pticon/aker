/*
 * Copyright © 2017, Pticon
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <pcap.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

#include "list.h"

#define PROGNAME	"aker"
#ifndef PATH_MAX
# define PATH_MAX	4096
#endif /* PATH_MAX */
#define VERSION		"1.0"
#define DEFAULT_CONF	"/usr/local/etc/aker.conf"
#define SEQUENCE_MAX	32
#define DEFAULT_TIMEOUT	5
#define PCAP_EXP_LEN	(SEQUENCE_MAX * 100)

#define FLAG_SYN	(1 << 0)
#define FLAG_RST	(1 << 1)
#define FLAG_FIN	(1 << 2)
#define FLAG_ACK	(1 << 3)
#define FLAG_PSH	(1 << 4)
#define FLAG_URG	(1 << 5)
#define FLAG_UDP	(1 << 6)

struct sequence
{
	unsigned short		port;
	unsigned		flags;
};

/* The port knocking sequence itself
 */
struct door
{
	char			name [PATH_MAX];
	char			cmd [PATH_MAX];
	struct sequence		seq [SEQUENCE_MAX];
	unsigned		seqcount;
	unsigned		flags;
	time_t			timeout;
	char			pcap_exp [PCAP_EXP_LEN];

	struct list_head	list;
};

/* The port knocking attempt
 */
struct try
{
	const struct door	*d;
	unsigned		ip;
	unsigned		seqcount;
	time_t			start;

	struct list_head	list;
};

/* Daemon state
 */
typedef enum
{
	DAEMON_RUN,
	DAEMON_STOP,
	DAEMON_RELOAD,
} status_t;

#define FMT_IPADDR	"%d.%d.%d.%d"
#define IPADDR(_ip)	((_ip)>>24)&0xff, ((_ip)>>16)&0xff, ((_ip)>>8)&0xff, (_ip)&0xff

/* Optim for GCC
 */
#ifdef __GNUC__
# define ATTR_PRINTF(_a, _b)     __attribute__ ((format(printf, _a, _b)))
#else
# define ATTR_PRINTF(_a, _b)
#endif /* __GNUC__ */

#ifdef __FreeBSD__
static char	interface [PATH_MAX] = "em0";
#else
static char	interface [PATH_MAX] = "eth0";
#endif /* __FreeBSD__ */
static char	logfile [PATH_MAX] = "/var/log/"PROGNAME".log";
static FILE	*flog = NULL;
static char	pidfile [PATH_MAX] = "/var/run/"PROGNAME".pid";
static char	startcmd [PATH_MAX] = "";
static char	stopcmd [PATH_MAX] = "";
static char	ipaddr [NI_MAXHOST] = "";
static		DEFINE_LIST_HEAD(doors);
static		DEFINE_LIST_HEAD(tries);
static pcap_t	*pcap = NULL;
static int	link_type = -1;
static status_t	status = DAEMON_RUN;


static void usage(void)
{
	printf("usage: %s [options]\n", PROGNAME);
	printf("options:\n");
	printf("\t-c <conffile> : default is %s\n", DEFAULT_CONF);
	printf("\t-f            : run in foreground (do not fork)\n");
	printf("\t-h            : display this and exit\n");
	printf("\t-t            : test the generated pcap filter and exit\n");
	printf("\t-v            : display version number and exit\n");
}

static void version(void)
{
	printf("%s v%s\n", PROGNAME, VERSION);
}

static void logger(const char *fmt, ...) ATTR_PRINTF(1, 2);
static void logger(const char *fmt, ...)
{
	time_t		t;
	struct tm	*tm;
	va_list		ap;

	t = time(NULL);
	tm = localtime(&t);

	fprintf(flog, "[%04d-%02d-%02d %02d:%02d] ", tm->tm_year+1900,
		tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min);

	va_start(ap, fmt);
	vfprintf(flog, fmt, ap);
	va_end(ap);

	fprintf(flog, "\n");

	fflush(flog);
}

static char *trim(char *str)
{
	char	*end;

	if ( str == NULL )
		return NULL;

	while ( isspace(*str) )
		str++;

	end = str + strlen(str) - 1;
	while ( end > str && isspace(*end) )
		*end = '\0', end--;

	return str;
}

static struct door *door_new(const char *name)
{
	struct door	*d;

	if ( (d = malloc(sizeof(struct door))) == NULL )
		return NULL;

	strncpy(d->name, name, sizeof(d->name));
	d->flags = 0;
	d->timeout = DEFAULT_TIMEOUT;
	d->seqcount = 0;
	d->pcap_exp[0] = '\0';

	INIT_LIST_HEAD(&d->list);

	return d;
}

static void door_free(struct door *d)
{
	if ( d == NULL )
		return;

	list_del(&d->list);

	free(d);
}

static struct try *try_new(unsigned ip)
{
	struct try	*t;

	if ( (t = malloc(sizeof(struct try))) == NULL )
		return NULL;

	t->ip = ip;
	t->seqcount = 0;

	INIT_LIST_HEAD(&t->list);

	list_add_tail(&t->list, &tries);

	return t;
}

static void try_free(struct try *t)
{
	if ( t == NULL )
		return;

	list_del(&t->list);

	free(t);
}

static struct try *try_find_by_ip(unsigned ip)
{
	struct try	*t;

	list_for_each_entry(t, &tries, list)
		if ( t->ip == ip )
			return t;

	return NULL;
}

static int parse_flags(unsigned *flags, char *value)
{
	char	*ptr;

	while ( (ptr = strsep(&value, ",")) )
	{
		if ( strcasecmp(ptr, "syn") == 0 )
			*flags |= FLAG_SYN;
		else if ( strcasecmp(ptr, "rst") == 0 )
			*flags |= FLAG_RST;
		else if ( strcasecmp(ptr, "fin") == 0 )
			*flags |= FLAG_FIN;
		else if ( strcasecmp(ptr, "ack") == 0 )
			*flags |= FLAG_ACK;
		else if ( strcasecmp(ptr, "psh") == 0 )
			*flags |= FLAG_PSH;
		else if ( strcasecmp(ptr, "urg") == 0 )
			*flags |= FLAG_URG;
		else if ( strcasecmp(ptr, "udp") == 0 )
			*flags |= FLAG_UDP;
		else
			return -1;
	}

	return 0;
}

static int parse_sequence(struct door *d, char *value)
{
	struct sequence	*sequence;
	char		*ptr;
	char		*endptr;
	long		val;

	while ( (ptr = strsep(&value, ",")) )
	{
		if ( d->seqcount >= SEQUENCE_MAX )
			return -1;

		sequence = &d->seq [d->seqcount++];

		errno = 0;
		val = strtol(ptr, &endptr, 10);

		if ( endptr == ptr )
			return -2;

		if ( (errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) ||
			(errno != 0 && val == 0) ||
			(errno == 0 && (val <= 0 || val >= 0xffff)) )
			return -3;

		sequence->port = val;
		sequence->flags = 0;

		if ( *endptr == '\0' )
			continue;

		/* Parse the flags within the port number.
		 * Valid syntax : "1234:syn/ack"
		 */
		if ( *endptr++ != ':' )
			return -2;

		while ( (ptr = strsep(&endptr, "/")) )
			if ( parse_flags(&sequence->flags, ptr) )
				return -4;
	}

	return 0;
}

static int parse_conf(const char *conffile)
{
	FILE		*f;
	int		ret = -1;
	char		str[PATH_MAX];
	char		section[PATH_MAX] = "";
	char		*ptr,
			*key,
			*value;
	int		line = 0;
	size_t		len;
	struct door	*d = NULL;

	if ( (f = fopen(conffile, "r")) == NULL )
	{
		fprintf(stderr, "Cannot open the config file %s\n", conffile);
		return ret;
	}

	while ( fgets(str, sizeof(str), f) )
	{
		line++;
		ptr = trim(str);
		len = strlen(ptr);

		/* Check comment and empty line
		 */
		if ( len == 0 || ptr[0] == '#' || ptr[0] == ';' )
			continue;

		/* Check new section
		 */
		if ( ptr[0] == '[' && ptr[len - 1] == ']' )
		{
			strncpy(section, ptr + 1, sizeof(section));
			section[len - 2] = '\0';

			if ( strcasecmp(section, "options") == 0 )
				continue;

			if ( d != NULL )
				list_add_tail(&d->list, &doors);

			if ( (d = door_new(section)) == NULL )
			{
				perror("malloc");
				goto error;
			}
			continue;
		}

		/* Check section name
		 */
		if ( strlen(section) == 0 )
		{
			fprintf(stderr, "%s:%d: No valid section defined\n",
				conffile, line);
			goto error;
		}

		/* Extract key/value pair
		 */
		key = trim(strsep(&ptr, "="));
		value = trim(ptr);
		if ( value == NULL )
		{
			fprintf(stderr, "%s:%d: syntax error\n", conffile, line);
			goto error;
		}

		/* Parse global options
		 */
		if ( strcasecmp(section, "options") == 0 )
		{
			if ( strcasecmp(key, "logfile") == 0 )
			{
				strncpy(logfile, value, sizeof(logfile));
			}
			else if ( strcasecmp(key, "pidfile") == 0 )
			{
				strncpy(pidfile, value, sizeof(pidfile));
			}
			else if ( strcasecmp(key, "ipaddr") == 0 )
			{
				strncpy(ipaddr, value, sizeof(ipaddr));
			}
			else if ( strcasecmp(key, "interface") == 0 )
			{
				strncpy(interface, value, sizeof(interface));
			}
			else if ( strcasecmp(key, "startcmd") == 0 )
			{
				strncpy(startcmd, value, sizeof(startcmd));
			}
			else if ( strcasecmp(key, "stopcmd") == 0 )
			{
				strncpy(stopcmd, value, sizeof(stopcmd));
			}
			else
			{
				fprintf(stderr, "%s:%d: unknown key %s\n",
					conffile, line, value);
				goto error;
			}
			continue;
		}

		if ( d == NULL )
		{
			fprintf(stderr, "%s:%d: \"%s\" can only be used within a"
				"section\n", conffile, line, key);
			goto error;
		}

		/* Add a new directive
		 */
		if ( strcasecmp(key, "command") == 0 )
		{
			strncpy(d->cmd, value, sizeof(d->cmd));
		}
		else if ( strcasecmp(key, "sequence") == 0 )
		{
			switch ( parse_sequence(d, value) )
			{
				case 0:
				break;

				case -1:
				fprintf(stderr, "%s:%d: too many sequences\n",
					conffile, line);
				goto error;

				case -2:
				fprintf(stderr, "%s:%d: no port number found\n",
					conffile, line);
				goto error;

				case -3:
				fprintf(stderr, "%s:%d: invalid port number\n",
					conffile, line);
				goto error;

				case -4:
				fprintf(stderr, "%s:%d: invalid flags\n",
					conffile, line);
				/* FALLTHROUGH
				 */

				default:
				goto error;
			}
		}
		else if ( strcasecmp(key, "timeout") == 0 )
		{
			d->timeout = atoi(value);
		}
		else if ( strcasecmp(key, "flags") == 0 )
		{
			if ( parse_flags(&d->flags, value) )
			{
				fprintf(stderr, "%s:%d: unknown flag\n",
					conffile, line);
				goto error;
			}
		}
		else
		{
			fprintf(stderr, "%s:%d: unknown key \"%s\"\n",
				conffile, line, key);
			goto error;
		}
	}

	if ( d != NULL )
		list_add_tail(&d->list, &doors);

	ret = 0;
error:
	fclose(f);

	return ret;
}

static int flags_are_global(const struct door *d)
{
	int			i;

	for ( i = 0 ; i < d->seqcount ; i++ )
		if ( d->seq[i].flags != 0 &&
			d->seq[i].flags != d->flags )
			return 0;

	return 1;
}

static void flagsncat(const unsigned flags, char *buf, size_t n)
{
	if ( flags & FLAG_SYN )
		strncat(buf, " and tcp[tcpflags] & tcp-syn != 0", n);

	if ( flags & FLAG_RST )
		strncat(buf, " and tcp[tcpflags] & tcp-rst != 0", n);

	if ( flags & FLAG_FIN )
		strncat(buf, " and tcp[tcpflags] & tcp-fin != 0", n);

	if ( flags & FLAG_ACK )
		strncat(buf, " and tcp[tcpflags] & tcp-ack != 0", n);

	if ( flags & FLAG_PSH )
		strncat(buf, " and tcp[tcpflags] & tcp-push != 0", n);

	if ( flags & FLAG_URG )
		strncat(buf, " and tcp[tcpflags] & tcp-urg != 0", n);
}

static int gen_pcap_filter(void)
{
	struct door		*d;
	int			i;
	char			buf [sizeof("65535")];
	char			filter [PATH_MAX];
	struct bpf_program	bpf;
	int			prev;
	unsigned		flags;

	/* Generate a subfilter for each door
	 */
	list_for_each_entry(d, &doors, list)
	{
		int	global_flags = flags_are_global(d);
		int	prev = 0;

		strncat(d->pcap_exp, "(", sizeof(d->pcap_exp));

		if ( strlen(ipaddr) )
		{
			strncat(d->pcap_exp, "(dst host ", sizeof(d->pcap_exp));
			strncat(d->pcap_exp, ipaddr, sizeof(d->pcap_exp));
			strncat(d->pcap_exp, ")", sizeof(d->pcap_exp));
			prev = 1;
		}

		if ( d->seqcount > 0 )
		{
			int	set = 0;

			if ( prev )
				strncat(d->pcap_exp, " and (", sizeof(d->pcap_exp));

			for ( i = 0 ; i < d->seqcount ; i++ )
			{
				if ( set++ )
					strncat(d->pcap_exp, " or ", sizeof(d->pcap_exp));

				flags = d->seq[i].flags != 0 ? d->seq[i].flags : d->flags;

				if ( (flags & ~FLAG_UDP) && !global_flags )
					strncat(d->pcap_exp, "( ", sizeof(d->pcap_exp));


				if ( (flags & FLAG_UDP) != 0 )
					strncat(d->pcap_exp, "udp dst port ", sizeof(d->pcap_exp));
				else
					strncat(d->pcap_exp, "tcp dst port ", sizeof(d->pcap_exp));

				snprintf(buf, sizeof(buf), "%d", d->seq[i].port);
				strncat(d->pcap_exp, buf, sizeof(d->pcap_exp));

				if ( (flags & ~FLAG_UDP) && !global_flags )
				{
					flagsncat(flags, d->pcap_exp, sizeof(d->pcap_exp));
					strncat(d->pcap_exp, " )", sizeof(d->pcap_exp));
				}
			}

			if ( prev )
				strncat(d->pcap_exp, ")", sizeof(d->pcap_exp));

			prev = 1;
		}

		if ( global_flags )
			flagsncat(d->flags, d->pcap_exp, sizeof(d->pcap_exp));

		strncat(d->pcap_exp, ")", sizeof(d->pcap_exp));
	}

	/* Append all of the subfilters in one filter
	 */
	prev = 0;
	filter [0] = '\0';
	list_for_each_entry(d, &doors, list)
	{
		if ( prev++ )
			strncat(filter, " and ", sizeof(filter) - strlen(filter) - 1);
		strncat(filter, d->pcap_exp, sizeof(filter) - strlen(filter) - 1);
	}
	printf("%s\n", filter);

	/* Compile the filter and set it
	 */
	if ( pcap_compile(pcap, &bpf, filter, 1, 0) < 0 )
	{
		pcap_perror(pcap, "pcap compile");
		return -1;
	}

	if ( pcap_setfilter(pcap, &bpf) < 0 )
	{
		pcap_perror(pcap, "pcap setfilter");
		pcap_freecode(&bpf);
		return -1;
	}

	pcap_freecode(&bpf);

	return 0;
}

static void sighandler(int sig)
{
	switch ( sig )
	{
		case SIGINT:
		case SIGTERM:
		status = DAEMON_STOP;
		pcap_breakloop(pcap);
		logger("Received signal %d: preparing to stop", sig);
		break;

		case SIGHUP:
		status = DAEMON_RELOAD;
		pcap_breakloop(pcap);
		logger("Received signal %d: reloading config", sig);
		break;

		default:
		logger("Received signal %d: ignoring", sig);
		break;
	}
}

static int setup_signals(void)
{
	if ( signal(SIGINT, sighandler) == SIG_ERR )
	{
		perror("signal");
		return -1;
	}

	if ( signal(SIGTERM, sighandler) == SIG_ERR )
	{
		perror("signal");
		return -1;
	}

	if ( signal(SIGHUP, sighandler) == SIG_ERR )
	{
		perror("signal");
		return -1;
	}

	return 0;
}


static void exec_door(const struct door *d, unsigned ip)
{
	char	cmd [PATH_MAX];
	char	*needle;
	int	len;

	if ( (needle = strcasestr(d->cmd, "%IP%")) != NULL )
	{
		len = snprintf(cmd, sizeof(cmd), "%.*s", (int)(needle - d->cmd), d->cmd);
		len += snprintf(cmd + len, sizeof(cmd) - len, FMT_IPADDR, IPADDR(ip));
		len += snprintf(cmd + len, sizeof(cmd) - len, " %s", needle + sizeof("%IP%"));
	}
	else
	{
		strncpy(cmd, d->cmd, sizeof(cmd));
	}

	logger("%s: execute command for " FMT_IPADDR ": %s", d->name, IPADDR(ip), cmd);
	system(cmd);
}


static int sanity_ether(const struct ether_header *eth, int *len)
{
	if ( *len < sizeof(*eth) || ntohs(eth->ether_type) != ETHERTYPE_IP )
		return 0;

	*len -= sizeof(*eth);

	return 1;
}


static int sanity_ip(const struct ip *ip, int *len)
{
	if ( *len < sizeof(*ip) )
		return 0;

	if ( ip->ip_v != 4 )
		return 0;

	if ( ip->ip_p != IPPROTO_TCP &&
		ip->ip_p != IPPROTO_UDP )
		return 0;

	if ( *len < ip->ip_hl * 4 )
		return 0;

	*len -= ip->ip_hl * 4;

	return ip->ip_p;
}


static int sanity_loopback(const uint32_t *loopback, int *len)
{
	if ( *len < sizeof(uint32_t) )
		return 0;

	if ( *loopback != AF_INET )
		return 0;

	*len -= sizeof(uint32_t);

	return 1;
}


static int sanity_tcp(const struct tcphdr *tcp, int *len)
{
	if ( *len < sizeof(*tcp) )
		return 0;

	return 1;
}

static int sanity_udp(const struct udphdr *udp, int *len)
{
	if ( *len < sizeof(*udp) )
		return 0;

	return 1;
}

static unsigned get_tcp_flags(const struct tcphdr *tcp)
{
	unsigned	flags = 0;

#ifdef __FreeBSD__
	if ( tcp->th_flags & TH_SYN ) flags |= FLAG_SYN;
	if ( tcp->th_flags & TH_RST ) flags |= FLAG_RST;
	if ( tcp->th_flags & TH_FIN ) flags |= FLAG_FIN;
	if ( tcp->th_flags & TH_ACK ) flags |= FLAG_ACK;
	if ( tcp->th_flags & TH_PUSH ) flags |= FLAG_PSH;
	if ( tcp->th_flags & TH_URG ) flags |= FLAG_URG;
#else
	if ( tcp->syn ) flags |= FLAG_SYN;
	if ( tcp->rst ) flags |= FLAG_RST;
	if ( tcp->fin ) flags |= FLAG_FIN;
	if ( tcp->ack ) flags |= FLAG_ACK;
	if ( tcp->psh ) flags |= FLAG_PSH;
	if ( tcp->urg ) flags |= FLAG_URG;
#endif /* __FreeBSD__ */

	return flags;
}

#ifdef __FreeBSD__
# define TCP_DEST_PORT(_tcp)	ntohs(_tcp->th_dport)
# define UDP_DEST_PORT(_udp)	ntohs(_udp->uh_dport)
#else
# define TCP_DEST_PORT(_tcp)	ntohs(_tcp->dest)
# define UDP_DEST_PORT(_udp)	ntohs(_udp->dest)
#endif /* __FreeBSD__ */

static void sniff(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes)
{
	int				len = hdr->caplen;
	const struct ether_header	*eth;
	const struct ip			*ip;
	const struct tcphdr		*tcp = NULL;
	const struct udphdr		*udp = NULL;
	struct try			*t,
					*ttmp;
	unsigned			srcip;
	struct door			*d;
	unsigned			flags;
	const uint32_t			*loopback;
	unsigned			dflags;

	/* Check the first layers
	 */
	switch ( link_type )
	{
		case DLT_EN10MB:
		eth = (const struct ether_header *) bytes;
		if ( !sanity_ether(eth, &len) )
			return;
		ip = (const struct ip *) (eth + 1);
		break;

		case DLT_NULL:
		loopback = (const uint32_t *) bytes;
		if ( !sanity_loopback(loopback, &len) )
			return;
		ip = (const struct ip *) (loopback + 1);
		break;

		default:
		return;
	}

	switch ( sanity_ip(ip, &len) )
	{
		case IPPROTO_UDP:
		udp = (const struct udphdr *) ((const u_char *)ip + (ip->ip_hl*4));
		if ( !sanity_udp(udp, &len) )
			return;
		break;

		case IPPROTO_TCP:
		tcp = (const struct tcphdr *) ((const u_char *)ip + (ip->ip_hl*4));
		if ( !sanity_tcp(tcp, &len) )
			return;
		break;

		default:
		return;
	}


	/* Cleanup the tries
	 */
	list_for_each_entry_safe(t, ttmp, &tries, list)
	{
		if ( t->start + t->d->timeout < hdr->ts.tv_sec )
		{
			logger("%s: timeout for " FMT_IPADDR " (%d) (timeout %d)" , t->d->name,
				IPADDR(ntohl(t->ip)), (int)(hdr->ts.tv_sec - t->start),
				(int)t->d->timeout);
			try_free(t);
		}
	}

	/* Extract infos
	 */
	srcip = ip->ip_src.s_addr;
	flags = tcp ? get_tcp_flags(tcp) : FLAG_UDP;

	/* Find back the try or allocate a new one
	 */
	if ( (t = try_find_by_ip(srcip)) == NULL )
	{
		int	found = 0;

		list_for_each_entry(d, &doors, list)
		{

			dflags = d->seq[0].flags != 0 ? d->seq[0].flags : d->flags;

			if ( dflags == flags &&
				( (tcp && d->seq[0].port == TCP_DEST_PORT(tcp)) ||
					(udp && d->seq[0].port == UDP_DEST_PORT(udp))))
			{
				found++;
				break;
			}
		}

		if ( !found )
			return;

		if ( (t = try_new(srcip)) == NULL )
			return;

		t->start = hdr->ts.tv_sec;
		t->d = d;
	}

	/* Update the entry on success and execute it if the sequence is completed
	 */
	dflags = t->d->seq[t->seqcount].flags != 0 ? t->d->seq[t->seqcount].flags : t->d->flags;

	if ( (tcp && t->d->seq[t->seqcount].port != TCP_DEST_PORT(tcp)) ||
		(udp && t->d->seq[t->seqcount].port != UDP_DEST_PORT(udp)) ||
		dflags != flags )
		return;

	if ( ++t->seqcount == t->d->seqcount )
	{
		exec_door(t->d, ntohl(srcip));
		try_free(t);
	}
}

static int sanity_check(void)
{
	struct door		*d;
	size_t			i;

	list_for_each_entry(d, &doors, list)
	{
		/* UDP and TCP is invalid
		 */
		if ( (d->flags & FLAG_UDP) != 0 &&
			(d->flags & ~FLAG_UDP) != 0 )
		{
			fprintf(stderr, "Section %s cannot be TCP and UDP.\n",
					d->name);
			return -1;
		}

		for ( i = 0 ; i < d->seqcount ; i++ )
			if ( (d->seq[i].flags & FLAG_UDP) != 0 &&
				(d->seq[i].flags & ~FLAG_UDP) != 0 )
			{
				fprintf(stderr, "Section %s cannot be TCP and UDP on the same port (eg: %u).\n",
						d->name, d->seq[i].port);
				return -1;
			}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	const char	*conffile = DEFAULT_CONF;
	int		opt,
			ret;
	struct door	*d,
			*tmp;
	struct try	*t,
			*ttmp;
	char		pcapbuf [PCAP_ERRBUF_SIZE];
	int		nofork = 0;
	int		test = 0;

	/* Parse command line arguments
	 */
	while ( (opt = getopt(argc, argv, "c:fhtv")) != -1 )
	{
		switch (opt)
		{
			case 'c':
			conffile = optarg;
			break;

			case 'f':
			nofork = 1;
			break;

			case 'h':
			usage();
			return 0;

			case 't':
			test = 1;
			break;

			case 'v':
			version();
			return 0;

			default:
			fprintf(stderr, "Unknown options %c\n", opt);
			return -1;
		}
	}

reload:
	/* Parse config file
	 */
	if ( (ret = parse_conf(conffile)) )
		goto error;

	/* Sanity check
	 */
	if ( (ret = sanity_check()) )
		goto error;

	/* Open the log file
	 */
	if ( (flog = fopen(logfile, "a")) == NULL )
	{
		fprintf(stderr, "Unable to open logfile %s.\n",
			logfile);
		goto error;
	}

	/* Open a live capture interface
	 */
	if ( (pcap = pcap_open_live(interface, 0, 0, 50, pcapbuf)) == NULL )
	{
		fprintf(stderr, "Could not open %s: %s\n",
			interface, pcapbuf);
		goto error;
	}

	/* Grab the link layer for the given interface
	 */
	switch ( (link_type = pcap_datalink(pcap)) )
	{
		case DLT_EN10MB:
		fprintf(stderr, "Ethernet interface detected\n");
		logger("%s: Ethernet interface detected", interface);
		break;

		case DLT_NULL:
		fprintf(stderr, "BSD Loopback interface detected\n");
		logger("%s: BSD Loopback interface detected", interface);
		break;

		default:
		fprintf(stderr, "Unknown interface type (%d)\n", link_type);
		goto error;
	}

	/* Prepare the PCAP filter
	 */
	if ( (ret = gen_pcap_filter()) )
		goto error;

	/* Execute the startcmd if any
	 */
	if ( strlen(startcmd) )
		system(startcmd);

	if ( test )
	{
		ret = 0;
		goto error;
	}

	/* Daemonize
	 */
	if ( !nofork )
	{
		pid_t	pid;

		if ( (pid = fork()) < 0 )
		{
			fprintf(stderr, "Unable to fork.\n");
			ret = -1;
			goto error;
		}

		/* It is the child
		 */
		if ( pid == 0 )
			;
		else
		{
			FILE	*f;

			if ( (f = fopen(pidfile, "w")) == NULL )
				fprintf(stderr, "Unable to open pidfile %s.\n",
					pidfile);
			else
			{
				fprintf(f, "%d\n", (int) pid);
				fclose(f);
			}

			return pid;
		}
	}

	/* Set signals
	 */
	if ( (ret = setup_signals()) )
		goto error;

	/* Process packets
	 */
	while ( status == DAEMON_RUN && (ret = pcap_dispatch(pcap, -1, sniff, NULL)) >= 0 )
		;

	switch ( status )
	{
		case DAEMON_RUN:
		/* Should not happen...
		 */
		break;

		case DAEMON_STOP:
		break;

		case DAEMON_RELOAD:
		nofork = 1;
		goto reload;
	}

	ret = 0;
error:
	/* Cleanup
	 */
	if ( strlen(stopcmd) )
		system(stopcmd);

	if ( pcap )
		pcap_close(pcap);

	list_for_each_entry_safe(t, ttmp, &tries, list)
		try_free(t);

	list_for_each_entry_safe(d, tmp, &doors, list)
		door_free(d);

	if ( flog )
		fclose(flog);

	unlink(pidfile);

	return 0;
}
