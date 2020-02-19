#include <algorithm>

#define __STDC_FORMAT_MACROS

#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <atomic>
#include <iomanip>

#include "tapyrus.h"
#include "db.h"
#include "dns.h"

using namespace std;

bool fTestNet = false;
std::map<int, CAddrDb*> dbs;
std::map<int, std::vector<std::string> > mSeeds;

class CDnsSeedOpts {
public:
    int nThreads;
    int nPort;
    int nDnsThreads;
    int fWipeBan;
    int fWipeIgnore;
    int networkid;
    const char *mbox;
    const char *ns;
    const char *host;
    const char *tor;
    const char *ipv4_proxy;
    const char *ipv6_proxy;
    std::set<uint64_t> filter_whitelist;
    std::vector<std::string> vSeeds;
    std::set<int> networks;

    CDnsSeedOpts() : nThreads(96), nDnsThreads(4), nPort(53), mbox(NULL), ns(NULL), host(NULL), tor(NULL), fWipeBan(false), fWipeIgnore(false), ipv4_proxy(NULL), ipv6_proxy(NULL), networkid(1) {}

    void ParseCommandLine(int argc, char **argv) {
        static const char *help = "Tapyrus-seeder\n"
                                  "Usage: %s -h <host> -n <ns> [-m <mbox>] [-t <threads>] [-p <port>]\n"
                                  "\n"
                                  "Options:\n"
                                  "-i <networkid>  Tapyrus network id to crawl(default 1)\n"
                                  "-s <seeds>      Other Tapyrus nodes to use for seeding\n"
                                  "-h <host>       Hostname of the DNS seed\n"
                                  "-n <ns>         Hostname of the nameserver\n"
                                  "-m <mbox>       E-Mail address reported in SOA records\n"
                                  "-t <threads>    Number of crawlers to run in parallel (default 96)\n"
                                  "-d <threads>    Number of DNS server threads (default 4)\n"
                                  "-p <port>       UDP port to listen on (default 53)\n"
                                  "-o <ip:port>    Tor proxy IP/Port\n"
                                  "-r <ip:port>    IPV4 SOCKS5 proxy IP/Port\n"
                                  "-k <ip:port>    IPV6 SOCKS5 proxy IP/Port\n"
                                  "-w f1,f2,...    Allow these flag combinations as filters\n"
                                  "--wipeban       Wipe list of banned nodes\n"
                                  "--wipeignore    Wipe list of ignored nodes\n"
                                  "-?, --help      Show this text\n"
                                  "\n";
        bool showHelp = false;

        while (1) {
            static struct option long_options[] = {
                    {"networkid",  required_argument, 0,             'i'},
                    {"seeds",      required_argument, 0,             's'},
                    {"host",       required_argument, 0,             'h'},
                    {"ns",         required_argument, 0,             'n'},
                    {"mbox",       required_argument, 0,             'm'},
                    {"threads",    required_argument, 0,             't'},
                    {"dnsthreads", required_argument, 0,             'd'},
                    {"port",       required_argument, 0,             'p'},
                    {"onion",      required_argument, 0,             'o'},
                    {"proxyipv4",  required_argument, 0,             'r'},
                    {"proxyipv6",  required_argument, 0,             'k'},
                    {"filter",      required_argument, 0,             'w'},
                    {"wipeban",    no_argument,       &fWipeBan,     1},
                    {"wipeignore", no_argument,       &fWipeBan,     1},
                    {"help",       no_argument,       0,             '?'},
                    {0, 0,                            0,             0}
            };
            int option_index = 0;
            int c = getopt_long(argc, argv, "i:s:h:n:m:t:p:d:o:r:k:w:?:", long_options, &option_index);
            if (c == -1) break;
            switch (c) {
                case 'i': {
                    int n = strtol(optarg, NULL, 10);
                    networks.emplace(n);
                    break;
                }

                case 's': {
                    vSeeds.push_back(optarg);
                    break;
                }

                case 'h': {
                    host = optarg;
                    break;
                }

                case 'm': {
                    mbox = optarg;
                    break;
                }

                case 'n': {
                    ns = optarg;
                    break;
                }

                case 't': {
                    int n = strtol(optarg, NULL, 10);
                    if (n > 0 && n < 1000) nThreads = n;
                    break;
                }

                case 'd': {
                    int n = strtol(optarg, NULL, 10);
                    if (n > 0 && n < 1000) nDnsThreads = n;
                    break;
                }

                case 'p': {
                    int p = strtol(optarg, NULL, 10);
                    if (p > 0 && p < 65536) nPort = p;
                    break;
                }

                case 'o': {
                    tor = optarg;
                    break;
                }

                case 'r': {
                    ipv4_proxy = optarg;
                    break;
                }

                case 'k': {
                    ipv6_proxy = optarg;
                    break;
                }

                case 'w': {
                    char *ptr = optarg;
                    while (*ptr != 0) {
                        unsigned long l = strtoul(ptr, &ptr, 0);
                        if (*ptr == ',') {
                            ptr++;
                        } else if (*ptr != 0) {
                            break;
                        }
                        filter_whitelist.insert(l);
                    }
                    break;
                }

                case '?': {
                    showHelp = true;
                    break;
                }
            }
        }
        if (filter_whitelist.empty()) {
            filter_whitelist.insert(1);
            filter_whitelist.insert(5);
            filter_whitelist.insert(9);
            filter_whitelist.insert(13);
        }
        if (host != NULL && ns == NULL) showHelp = true;
        if (showHelp)
        {
            fprintf(stderr, help, argv[0]);
            exit(0);
        }
    }
};


struct ThreadCrawler_options
{
    int nThreads;
    int nNetworkId;
};

extern "C" void *ThreadCrawler(void *data) {
    ThreadCrawler_options *threadOpts = (ThreadCrawler_options*)data;
    const int nThreads = threadOpts->nThreads;
    const int nNetworkId = threadOpts->nNetworkId;
    CAddrDb *db = dbs.find(nNetworkId)->second;

    do {
        std::vector<CServiceResult> ips;
        int wait = 5;
        db->GetMany(ips, 16, wait);
        int64 now = time(NULL);
        if (ips.empty()) {
            wait *= 1000;
            wait += rand() % (500 * nThreads);
            Sleep(wait);
            continue;
        }
        vector<CAddress> addr;
        for (int i = 0; i < ips.size(); i++) {
            CServiceResult &res = ips[i];
            res.nBanTime = 0;
            res.nClientV = 0;
            res.nHeight = 0;
            res.strClientV = "";
            bool getaddr = res.ourLastSuccess < now;
            res.fGood = TestNode(res.service, res.nBanTime, res.nClientV, res.strClientV, res.nHeight,
                                 getaddr ? &addr : NULL, nNetworkId);
        }
        db->ResultMany(ips);
        db->Add(addr);
    } while (1);
    return nullptr;
}

extern "C" int GetIPList(void *thread, char *requestedHostname, addr_t *addr, int max, int ipv4, int ipv6);

class CDnsThread {
public:
    struct FlagSpecificData {
        int nIPv4, nIPv6;
        std::vector<addr_t> cache;
        time_t cacheTime;
        unsigned int cacheHits;

        FlagSpecificData() : nIPv4(0), nIPv6(0), cacheTime(0), cacheHits(0) {}
    };

    dns_opt_t dns_opt; // must be first
    const int id;
    const int network;
    std::map<uint64_t, FlagSpecificData> perflag;
    std::atomic<uint64_t> dbQueries;
    std::set<uint64_t> filterWhitelist;

    void cacheHit(uint64_t requestedFlags, bool force = false) {
        CAddrDb *db = dbs.find(network)->second;
        static bool nets[NET_MAX] = {};
        if (!nets[NET_IPV4]) {
            nets[NET_IPV4] = true;
            nets[NET_IPV6] = true;
        }
        time_t now = time(NULL);
        FlagSpecificData &thisflag = perflag[requestedFlags];
        thisflag.cacheHits++;
        if (force || thisflag.cacheHits * 400 > (thisflag.cache.size() * thisflag.cache.size()) ||
            (thisflag.cacheHits * thisflag.cacheHits * 20 > thisflag.cache.size() && (now - thisflag.cacheTime > 5))) {
            set<CNetAddr> ips;
            db->GetIPs(ips, requestedFlags, 1000, nets);
            dbQueries++;
            thisflag.cache.clear();
            thisflag.nIPv4 = 0;
            thisflag.nIPv6 = 0;
            thisflag.cache.reserve(ips.size());
            for (set<CNetAddr>::iterator it = ips.begin(); it != ips.end(); it++) {
                struct in_addr addr;
                struct in6_addr addr6;
                if ((*it).GetInAddr(&addr)) {
                    addr_t a;
                    a.v = 4;
                    memcpy(&a.data.v4, &addr, 4);
                    thisflag.cache.push_back(a);
                    thisflag.nIPv4++;
                } else if ((*it).GetIn6Addr(&addr6)) {
                    addr_t a;
                    a.v = 6;
                    memcpy(&a.data.v6, &addr6, 16);
                    thisflag.cache.push_back(a);
                    thisflag.nIPv6++;
                }
            }
            thisflag.cacheHits = 0;
            thisflag.cacheTime = now;
        }
    }

    CDnsThread(CDnsSeedOpts *opts, int idIn, int networkIn) : id(idIn), network(networkIn) {
        dns_opt.host = opts->host;
        dns_opt.ns = opts->ns;
        dns_opt.mbox = opts->mbox;
        dns_opt.datattl = 3600;
        dns_opt.nsttl = 40000;
        dns_opt.cb = GetIPList;
        dns_opt.port = opts->nPort;
        dns_opt.nRequests = 0;
        dbQueries = 0;
        perflag.clear();
        filterWhitelist = opts->filter_whitelist;
    }

    void run() {
        dnsserver(&dns_opt);
    }
};

extern "C" int GetIPList(void *data, char *requestedHostname, addr_t *addr, int max, int ipv4, int ipv6) {
    CDnsThread *thread = (CDnsThread *) data;

    uint64_t requestedFlags = 0;
    int hostlen = strlen(requestedHostname);
    if (hostlen > 1 && requestedHostname[0] == 'x' && requestedHostname[1] != '0') {
        char *pEnd;
        uint64_t flags = (uint64_t) strtoull(requestedHostname + 1, &pEnd, 16);
        if (*pEnd == '.' && pEnd <= requestedHostname + 17 &&
            std::find(thread->filterWhitelist.begin(), thread->filterWhitelist.end(), flags) !=
            thread->filterWhitelist.end())
            requestedFlags = flags;
        else
            return 0;
    } else if (strcasecmp(requestedHostname, thread->dns_opt.host))
        return 0;
    thread->cacheHit(requestedFlags);
    auto &thisflag = thread->perflag[requestedFlags];
    unsigned int size = thisflag.cache.size();
    unsigned int maxmax = (ipv4 ? thisflag.nIPv4 : 0) + (ipv6 ? thisflag.nIPv6 : 0);
    if (max > size)
        max = size;
    if (max > maxmax)
        max = maxmax;
    int i = 0;
    while (i < max) {
        int j = i + (rand() % (size - i));
        do {
            bool ok = (ipv4 && thisflag.cache[j].v == 4) ||
                      (ipv6 && thisflag.cache[j].v == 6);
            if (ok) break;
            j++;
            if (j == size)
                j = i;
        } while (1);
        addr[i] = thisflag.cache[j];
        thisflag.cache[j] = thisflag.cache[i];
        thisflag.cache[i] = addr[i];
        i++;
    }
    return max;
}

vector<CDnsThread *> dnsThread;

extern "C" void *ThreadDNS(void *arg) {
    CDnsThread *thread = (CDnsThread *) arg;
    thread->run();
    return nullptr;
}

int StatCompare(const CAddrReport &a, const CAddrReport &b) {
    if (a.uptime[4] == b.uptime[4]) {
        if (a.uptime[3] == b.uptime[3]) {
            return a.clientVersion > b.clientVersion;
        } else {
            return a.uptime[3] > b.uptime[3];
        }
    } else {
        return a.uptime[4] > b.uptime[4];
    }
}

extern "C" void *ThreadDumper(void *arg) {
    std::set<int> *networks = (std::set<int> *)arg;

    do {

        for(auto network:*networks)
        {
            CAddrDb *db = dbs.find(network)->second;
            int count = 0;
            char filename[25] = {};
            sprintf(filename, "tapyrusseed.dat.%d", network);

            Sleep(100000 << count); // First 100s, than 200s, 400s, 800s, 1600s, and then 3200s forever
            if (count < 5)
                count++;
            {
                vector<CAddrReport> v = db->GetAll();
                sort(v.begin(), v.end(), StatCompare);
                FILE *f = fopen("tapyrusseed.dat.new", "w+");
                if (f) {
                    {
                        CAutoFile cf(f);
                        cf << *db;
                    }
                    rename("tapyrusseed.dat.new", filename);
                }
                sprintf(filename, "tapyrusseed.dump.%d", network);
                FILE *d = fopen(filename, "w");
                fprintf(d,
                        "# address                                        good  lastSuccess    %%(2h)   %%(8h)   %%(1d)   %%(7d)  %%(30d)  blocks      svcs  version\n");
                double stat[5] = {0, 0, 0, 0, 0};
                for (vector<CAddrReport>::const_iterator it = v.begin(); it < v.end(); it++) {
                    CAddrReport rep = *it;
                    fprintf(d,
                            "%-47s  %4d  %11" PRId64 "  %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%%  %6i  %08" PRIx64 "  %5i \"%s\"\n",
                            rep.ip.ToString().c_str(), (int) rep.fGood, rep.lastSuccess, 100.0 * rep.uptime[0],
                            100.0 * rep.uptime[1], 100.0 * rep.uptime[2], 100.0 * rep.uptime[3], 100.0 * rep.uptime[4],
                            rep.blocks, rep.services, rep.clientVersion, rep.clientSubVersion.c_str());
                    stat[0] += rep.uptime[0];
                    stat[1] += rep.uptime[1];
                    stat[2] += rep.uptime[2];
                    stat[3] += rep.uptime[3];
                    stat[4] += rep.uptime[4];
                }
                fclose(d);
                FILE *ff = fopen("tapyrusdnsstats.log", "a");
                fprintf(ff, "%llu %g %g %g %g %g\n", (unsigned long long) (time(NULL)), stat[0], stat[1], stat[2], stat[3],
                        stat[4]);
                fclose(ff);
            }
        }

    } while (1);
    return nullptr;
}

extern "C" void *ThreadStats(void *arg) {
    std::set<int> *networks = (std::set<int> *)arg;

    bool first = true;
    do {
        char c[256];
        uint64_t requests = 0;
        uint64_t queries = 0;
        std::ostringstream displayStr;

        time_t tim = time(NULL);
        struct tm *tmp = localtime(&tim);
        strftime(c, 256, "[%y-%m-%d %H:%M:%S]", tmp);

        displayStr << std::setw(20) << c
                   << std::setw(18) << "Elapsed time(s)"
                   << std::setw(15) << "Network ID"
                   << std::setw(11) << "Available"
                   << std::setw(11) << "Tried"
                   << std::setw(11) << "New"
                   << std::setw(11) << "Active"
                   << std::setw(11) << "Banned"
                   << std::setw(15) << "DNS requests"
                   << std::setw(15) << "db queries\n";

        for(auto network:*networks)
        {
            CAddrDbStats stats;
            CAddrDb *db = dbs.find(network)->second;
            db->GetStats(stats);
            requests = 0;
            queries = 0;
            for (unsigned int i = 0; i < dnsThread.size(); i++) {
                requests += dnsThread[i]->dns_opt.nRequests;
                queries += dnsThread[i]->dbQueries;
            }
            displayStr << std::setw(20) << ""
                       << std::setw(18) << stats.nAge
                       << std::setw(15) << network
                       << std::setw(5) << stats.nGood << "/" << std::setw(5) << std::left << stats.nAvail
                       << std::setw(11) << std::right << stats.nTracked
                       << std::setw(11) << stats.nNew
                       << std::setw(11) << stats.nAvail - stats.nTracked - stats.nNew
                       << std::setw(11) << stats.nBanned
                       << std::setw(15) << (unsigned long long) requests
                       << std::setw(15) << (unsigned long long) queries
                       << "\n";
        }
        if (first) {
            first = false;
            printf("\n\n\n\n\n\x1b[3A");
        } else
            printf("\n\n\x1b[2K\x1b[u");
        printf("\x1b[s");
        printf("%s", displayStr.str().c_str());
        Sleep(1000);

    } while (1);
    return nullptr;
}

struct ThreadSeeder_options
{
    std::map<int, std::vector<std::string> > *mSeeds;
    int size;
};

extern "C" void *ThreadSeeder(void *args) {
    ThreadSeeder_options* options = (ThreadSeeder_options*)args;
    const std::map<int, std::vector<std::string> > *mSeeds = options->mSeeds;
    const int size = options->size;

    vector<CNetAddr> ips;
    do {
        for (auto &seedEnt:*mSeeds)
        {
            CAddrDb *db = dbs.find(seedEnt.first)->second;
            for (auto& seed : seedEnt.second) {
                ips.clear();
                auto pos = seed.find(':');
                if(pos != std::string::npos)
                    db->Add(CService(seed), true);
                else
                {
                    LookupHost(seed.c_str(), ips);
                    for (vector<CNetAddr>::iterator it = ips.begin(); it != ips.end(); it++) {
                        db->Add(CService(*it, TAPYRUS_DEFAULT_PORT), true);
                    }
                }
            }
        }
        Sleep(3 * 60 * 1000);
    } while (1);
    return nullptr;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    setbuf(stdout, NULL);
    CDnsSeedOpts opts;
    opts.ParseCommandLine(argc, argv);
    bool fDNS = true;
    if (!opts.ns) {
        printf("No nameserver set. Not starting DNS server.\n");
        fDNS = false;
    }
    if (fDNS && !opts.host) {
        fprintf(stderr, "No hostname set. Please use -h.\n");
        exit(1);
    }
    if (fDNS && !opts.mbox) {
        fprintf(stderr, "No e-mail address set. Please use -m.\n");
        exit(1);
    }

    std::ostringstream  networkstr;
    for(auto networkId:opts.networks)
        networkstr << networkId << " ";
    printf("Supporting networks : %s\n", networkstr.str().c_str());

    std::ostringstream whitelistedstr;
    for(auto flag:opts.filter_whitelist)
        whitelistedstr << std::hex << "0x"<< flag << " ";
    printf("Supporting whitelisted filters: %s\n", whitelistedstr.str().c_str());

    if (opts.tor) {
        CService service(opts.tor, 9050);
        if (service.IsValid()) {
            printf("Using Tor proxy at %s\n", service.ToStringIPPort().c_str());
            SetProxy(NET_TOR, service);
        }
    }
    if (opts.ipv4_proxy) {
        CService service(opts.ipv4_proxy, 9050);
        if (service.IsValid()) {
            printf("Using IPv4 proxy at %s\n", service.ToStringIPPort().c_str());
            SetProxy(NET_IPV4, service);
        }
    }
    if (opts.ipv6_proxy) {
        CService service(opts.ipv6_proxy, 9050);
        if (service.IsValid()) {
            printf("Using IPv6 proxy at %s\n", service.ToStringIPPort().c_str());
            SetProxy(NET_IPV6, service);
        }
    }

    //parse opts.vSeeds and get the seeder name for each network.
    std::vector<std::string> seedTmp;
    for(auto network:opts.networks)
    {
        seedTmp.clear();
        for(auto &seed:opts.vSeeds)
        {
            if(std::stoi(seed.substr(0, seed.find(":"))) == network)
                seedTmp.push_back(seed.substr(seed.find(":")+1));
        }
        mSeeds.emplace(network, seedTmp);
    }

    //find networks for which there is no seeder (-s).
    std::set<int> missing;
    for(auto network:opts.networks)
        if(!mSeeds[network].size())
            missing.emplace(network);

    //initialize the DB for each network
    for(auto network:opts.networks)
        dbs[network] = new CAddrDb();

    //load stats of networks for which there is no tapyrusseed.dat.
    for(auto network: opts.networks)
    {
        char filename[25] = {};
        sprintf(filename, "tapyrusseed.dat.%d", network);
        FILE *f = fopen(filename, "r");
        if (f) {
            CAddrDb *db = dbs.find(network)->second;
            printf("Loading %s...", filename);
            CAutoFile cf(f);
            cf >> *db;
            if (opts.fWipeBan)
                db->banned.clear();
            if (opts.fWipeIgnore)
                db->ResetIgnores();
            printf("done\n");
            missing.erase(network);
        }
    }

    //if there are networks without tapyrusseed.dat and -s exit
    if(missing.size()) {
        printf("\nDNS information file, tapyrusseed.dat.<networkId> missing for some networks and number of initial DNS seeders do not match the number of networks served.\nPlease provide at least one -s <network_id>:<seeder_ip_address> for each of the networks configured using -i.\n");
        exit(1);
    }

    pthread_t threadDns, threadSeed, threadDump, threadStats;

    printf("Starting seeder...");
    ThreadSeeder_options threadOpts;
    threadOpts.mSeeds = &mSeeds;
    threadOpts.size = opts.networks.size();
    pthread_create(&threadSeed, NULL, ThreadSeeder, &threadOpts);
    printf("done\n");

    int i = 0;
    std::set<int>::iterator iter = opts.networks.begin();
    if (fDNS) {
        printf("Starting %i DNS threads for %s on %s (port %i)...", opts.nDnsThreads, opts.host, opts.ns, opts.nPort);
        dnsThread.clear();
        for (i = 0; i < opts.nDnsThreads; i++) {
            dnsThread.push_back(new CDnsThread(&opts, i, *iter));
            pthread_create(&threadDns, NULL, ThreadDNS, dnsThread[i]);
            ++iter;
            if(iter == opts.networks.end())
                iter = opts.networks.begin();
            printf(".");
            Sleep(20);
        }
        printf("done\n");
    }

    printf("Starting %i crawler threads...", opts.nThreads);
    pthread_attr_t attr_crawler;
    pthread_attr_init(&attr_crawler);
    pthread_attr_setstacksize(&attr_crawler, 0x20000);
    iter = opts.networks.begin();
    for (i = 0; i < opts.nThreads; i++) {
        pthread_t thread;
        ThreadCrawler_options threadOpts;
        threadOpts.nThreads = opts.nThreads;
        threadOpts.nNetworkId = *iter;
        pthread_create(&thread, &attr_crawler, ThreadCrawler, &threadOpts);
        ++iter;
        if(iter == opts.networks.end())
            iter = opts.networks.begin();
    }
    pthread_attr_destroy(&attr_crawler);
    printf("done\n");
    pthread_create(&threadStats, NULL, ThreadStats, &opts.networks);
    pthread_create(&threadDump, NULL, ThreadDumper, &opts.networks);
    printf("Tapyrus Seeder Ready");
    void *res;
    pthread_join(threadDump, &res);
    return 0;
}
