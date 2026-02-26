/* =============================================================
 *  manet-routing-metrics.cc  –  NS3 3.39
 *  Original metrics  : PDR | Delay | Jitter | Throughput
 *  New routing metrics: Hop Count | TTL | Route Discovery Time
 *                       Routing Overhead | NRL | Control Bytes
 * ============================================================= */

// ─────────────────────────────────────────────────────────────
//  ROUTING  1=AODV  2=OLSR  3=DSR  4=DSDV
// ─────────────────────────────────────────────────────────────
#define ROUTING_PROTOCOL   1

// ─────────────────────────────────────────────────────────────
//  TOPOLOGY   GRID_TYPE 1=1-D  2=2-D
// ─────────────────────────────────────────────────────────────
#define GRID_TYPE          2
#define INTER_NODE_GAP     50.0

// ─────────────────────────────────────────────────────────────
//  MOBILITY   1=RandomWaypoint  2=Static  3=GaussMarkov
// ─────────────────────────────────────────────────────────────
#define MOBILITY_MODEL     2
#define NODE_SPEED_MIN     1.0
#define NODE_SPEED_MAX     20.0
#define NODE_PAUSE_MIN     0.0
#define NODE_PAUSE_MAX     2.0

// ─────────────────────────────────────────────────────────────
//  SIMULATION
// ─────────────────────────────────────────────────────────────
#define NUM_NODES          10
#define SIM_TIME           30.0
#define PACKET_SIZE        512
#define PACKET_INTERVAL    0.1
#define APP_START          1.0
#define APP_STOP           29.0
#define TX_POWER_DBM       20.0
#define INITIAL_TTL        64      // NS3 default IPv4 TTL
#define DATA_PORT          9       // UDP port used by UdpClient

// ─────────────────────────────────────────────────────────────
//  SWEEP   SWEEP_PARAM 0=none 1=NumNodes 2=Speed 3=Gap
// ─────────────────────────────────────────────────────────────
#define SWEEP_PARAM        1
#define SWEEP_START        5
#define SWEEP_END          30
#define SWEEP_STEP         5

// ─────────────────────────────────────────────────────────────
//  OUTPUT
// ─────────────────────────────────────────────────────────────
#define OUTPUT_PREFIX      "manet-run"
#define ENABLE_PCAP        1
#define ENABLE_FLOWMON     1
#define APP_LOG_FILE       "app-layer-stats.csv"
#define ROUTING_LOG_FILE   "routing-stats.csv"

// =============================================================
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/seq-ts-header.h"
#include "ns3/ipv4-l3-protocol.h"   // SendOutgoing / LocalDeliver traces
#include "ns3/udp-header.h"          // UdpHeader peek in callbacks
#include "ns3/ipv4-header.h"         // Ipv4Header in trace signatures

#if ROUTING_PROTOCOL == 1
  #include "ns3/aodv-module.h"
#elif ROUTING_PROTOCOL == 2
  #include "ns3/olsr-module.h"
#elif ROUTING_PROTOCOL == 3
  #include "ns3/dsr-module.h"
#elif ROUTING_PROTOCOL == 4
  #include "ns3/dsdv-module.h"
#else
  #error "ROUTING_PROTOCOL must be 1 2 3 or 4"
#endif

#include <fstream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <map>
#include <string>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE ("ManetRoutingMetrics");

// =============================================================
//  STRUCTS
// =============================================================

struct AppStats {
    uint32_t txPkts   = 0;
    uint32_t rxPkts   = 0;
    double   rxBytes  = 0;
    double   sumDelay = 0;
    double   sumJit   = 0;
    double   lastDly  = -1.0;
};

struct RoutingStats {
    // Hop count / TTL  (measured at LocalDeliver on sink)
    uint32_t hopSum   = 0;
    uint32_t hopCnt   = 0;
    uint32_t hopMin   = 255;
    uint32_t hopMax   = 0;
    uint32_t ttlSum   = 0;

    // Route discovery time
    // = wall-clock of first RxCb  -  wall-clock of first TxCb
    double   firstTxT = -1.0;
    double   firstRxT = -1.0;

    // Routing overhead (from SendOutgoing on ALL nodes)
    uint64_t totalIpTx  = 0;   // all IP packets sent
    uint64_t dataIpTx   = 0;   // only UDP port DATA_PORT
    uint64_t ctrlIpTx   = 0;   // everything else = control
    uint64_t totalIpB   = 0;   // total bytes (payload+hdr)
    uint64_t ctrlIpB    = 0;   // control bytes
};

// ── Globals (reset per RunOnce) ───────────────────────────────
static std::map<uint32_t, AppStats> g_rx;
static std::map<uint32_t, AppStats> g_tx;
static RoutingStats                 g_rstat;

// =============================================================
//  APP-LAYER CALLBACKS  (plain static – required by NS3)
// =============================================================

static void TxCb (uint32_t srcIdx, Ptr<const Packet> pkt)
{
    g_tx[srcIdx].txPkts++;
    // record first-packet send time for route discovery metric
    if (g_rstat.firstTxT < 0.0)
        g_rstat.firstTxT = Simulator::Now ().GetSeconds ();
}

static void RxCb (uint32_t dstIdx, Ptr<const Packet> pkt)
{
    SeqTsHeader hdr;
    Ptr<Packet> cp = pkt->Copy ();
    cp->RemoveHeader (hdr);

    double txT = hdr.GetTs ().GetSeconds ();
    double rxT = Simulator::Now ().GetSeconds ();
    double dly = (rxT - txT > 0) ? (rxT - txT) : 0.0;

    AppStats &s = g_rx[dstIdx];
    s.rxPkts++;
    s.rxBytes  += (double)pkt->GetSize ();
    s.sumDelay += dly;
    if (s.lastDly >= 0.0)
        s.sumJit += std::fabs (dly - s.lastDly);
    s.lastDly = dly;

    // first-packet receive time for route discovery metric
    if (g_rstat.firstRxT < 0.0)
        g_rstat.firstRxT = rxT;
}

// =============================================================
//  ROUTING-LAYER CALLBACKS
// =============================================================

// ── LocalDeliver at SINK  →  TTL / Hop Count ─────────────────
// Fires with Ipv4Header still intact; only for packets destined
// for a local socket on that node.
static void Ipv4LocalDeliverCb (const Ipv4Header &iph,
                                 Ptr<const Packet> pkt,
                                 uint32_t /*iface*/)
{
    if (iph.GetProtocol () != 17) return;   // UDP only

    Ptr<Packet> cp = pkt->Copy ();
    UdpHeader   udph;
    if (cp->GetSize () < 8) return;
    cp->PeekHeader (udph);
    if (udph.GetDestinationPort () != DATA_PORT) return;

    uint8_t ttl  = iph.GetTtl ();
    uint8_t hops = (INITIAL_TTL > ttl) ? (INITIAL_TTL - ttl) : 0;

    g_rstat.ttlSum += ttl;
    g_rstat.hopSum += hops;
    g_rstat.hopCnt++;
    if (hops < g_rstat.hopMin) g_rstat.hopMin = hops;
    if (hops > g_rstat.hopMax) g_rstat.hopMax = hops;
}

// ── SendOutgoing on ALL nodes  →  Routing Overhead ───────────
// Fires for every IP packet a node originates or forwards.
// Ipv4Header is provided directly – no need to parse the packet.
static void Ipv4SendOutgoingCb (const Ipv4Header &iph,
                                 Ptr<const Packet> pkt,
                                 uint32_t /*iface*/)
{
    uint32_t sz = pkt->GetSize () + iph.GetSerializedSize ();
    g_rstat.totalIpTx++;
    g_rstat.totalIpB += sz;

    bool isData = false;
    if (iph.GetProtocol () == 17) {       // UDP
        Ptr<Packet> cp = pkt->Copy ();
        UdpHeader udph;
        if (cp->GetSize () >= 8) {
            cp->PeekHeader (udph);
            if (udph.GetDestinationPort () == DATA_PORT)
                isData = true;
        }
    }

    if (isData) {
        g_rstat.dataIpTx++;
    } else {
        g_rstat.ctrlIpTx++;
        g_rstat.ctrlIpB += sz;
    }
}

// =============================================================
//  GRID + MOBILITY
// =============================================================

static void PlaceGrid (NodeContainer &nodes, int n, double gap)
{
    Ptr<ListPositionAllocator> pos = CreateObject<ListPositionAllocator> ();

#if GRID_TYPE == 1
    for (int i = 0; i < n; i++)
        pos->Add (Vector (i * gap, 0.0, 0.0));
#else
    int cols = (int)std::ceil (std::sqrt ((double)n));
    for (int i = 0; i < n; i++)
        pos->Add (Vector ((i % cols) * gap, (i / cols) * gap, 0.0));
#endif

    MobilityHelper mob;
    mob.SetPositionAllocator (pos);

#if MOBILITY_MODEL == 1
    {
        double area = n * gap * 1.5;
        std::ostringstream sv, pv;
        sv << "ns3::UniformRandomVariable[Min=" << NODE_SPEED_MIN
           << "|Max=" << NODE_SPEED_MAX << "]";
        pv << "ns3::UniformRandomVariable[Min=" << NODE_PAUSE_MIN
           << "|Max=" << NODE_PAUSE_MAX << "]";
        Ptr<RandomRectanglePositionAllocator> rpa =
            CreateObject<RandomRectanglePositionAllocator> ();
        rpa->SetAttribute ("X", StringValue (
            "ns3::UniformRandomVariable[Min=0|Max=" + std::to_string (area) + "]"));
        rpa->SetAttribute ("Y", StringValue (
            "ns3::UniformRandomVariable[Min=0|Max=" + std::to_string (area) + "]"));
        mob.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
                              "Speed",             StringValue (sv.str ()),
                              "Pause",             StringValue (pv.str ()),
                              "PositionAllocator", PointerValue (rpa));
    }
#elif MOBILITY_MODEL == 2
    mob.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
#elif MOBILITY_MODEL == 3
    {
        double area = n * gap * 1.5;
        std::ostringstream vv;
        vv << "ns3::UniformRandomVariable[Min=" << NODE_SPEED_MIN
           << "|Max=" << NODE_SPEED_MAX << "]";
        mob.SetMobilityModel (
            "ns3::GaussMarkovMobilityModel",
            "Bounds",       BoxValue (Box (0, area, 0, area, 0, 0)),
            "TimeStep",     TimeValue (Seconds (0.5)),
            "Alpha",        DoubleValue (0.85),
            "MeanVelocity", StringValue (vv.str ()),
            "MeanDirection",StringValue ("ns3::UniformRandomVariable[Min=0|Max=6.283185]"),
            "MeanPitch",    StringValue ("ns3::UniformRandomVariable[Min=0.05|Max=0.05]"));
    }
#else
    #error "MOBILITY_MODEL must be 1 2 or 3"
#endif

    mob.Install (nodes);
}

// =============================================================
//  HELPERS
// =============================================================

static std::string Ip2Str (Ipv4Address a)
{
    std::ostringstream os; a.Print (os); return os.str ();
}

// =============================================================
//  SINGLE RUN
// =============================================================

static void RunOnce (int runId, int numNodes, double /*speed*/, double gap,
                     std::ofstream &appLog, std::ofstream &routingLog)
{
    g_rx.clear ();
    g_tx.clear ();
    g_rstat = RoutingStats ();      // reset all routing counters

    // ── Nodes ─────────────────────────────────────────────────
    NodeContainer nodes;
    nodes.Create (numNodes);

    // ── WiFi ad-hoc ───────────────────────────────────────────
    WifiHelper wifi;
    wifi.SetStandard (WIFI_STANDARD_80211b);
    wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                  "DataMode",    StringValue ("DsssRate11Mbps"),
                                  "ControlMode", StringValue ("DsssRate1Mbps"));

    YansWifiPhyHelper phy;
    phy.Set ("TxPowerStart", DoubleValue (TX_POWER_DBM));
    phy.Set ("TxPowerEnd",   DoubleValue (TX_POWER_DBM));
    YansWifiChannelHelper ch = YansWifiChannelHelper::Default ();
    phy.SetChannel (ch.Create ());

    WifiMacHelper mac;
    mac.SetType ("ns3::AdhocWifiMac");
    NetDeviceContainer devs = wifi.Install (phy, mac, nodes);

    // ── Mobility ──────────────────────────────────────────────
    PlaceGrid (nodes, numNodes, gap);

    // ── Internet Stack + Routing ──────────────────────────────
    InternetStackHelper internet;

#if ROUTING_PROTOCOL == 1
    { AodvHelper r; internet.SetRoutingHelper (r); internet.Install (nodes); }
#elif ROUTING_PROTOCOL == 2
    { OlsrHelper r; internet.SetRoutingHelper (r); internet.Install (nodes); }
#elif ROUTING_PROTOCOL == 3
    { DsrHelper dsr; DsrMainHelper dm; internet.Install (nodes); dm.Install (dsr, nodes); }
#elif ROUTING_PROTOCOL == 4
    { DsdvHelper r; internet.SetRoutingHelper (r); internet.Install (nodes); }
#endif

    // ── IP Addresses ──────────────────────────────────────────
    Ipv4AddressHelper addrH;
    addrH.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = addrH.Assign (devs);

    uint32_t srcIdx = 0;
    uint32_t dstIdx = (uint32_t)(numNodes - 1);

    // ── Hook IP traces AFTER internet stack installed ──────────

    // LocalDeliver at sink  →  TTL / hop count
    {
        Ptr<Ipv4L3Protocol> ip =
            nodes.Get (dstIdx)->GetObject<Ipv4L3Protocol> ();
        if (ip)
            ip->TraceConnectWithoutContext (
                "LocalDeliver", MakeCallback (&Ipv4LocalDeliverCb));
    }

    // SendOutgoing on ALL nodes  →  routing overhead
    for (uint32_t i = 0; i < (uint32_t)numNodes; i++) {
        Ptr<Ipv4L3Protocol> ip =
            nodes.Get (i)->GetObject<Ipv4L3Protocol> ();
        if (ip)
            ip->TraceConnectWithoutContext (
                "SendOutgoing", MakeCallback (&Ipv4SendOutgoingCb));
    }

    // ── Applications ──────────────────────────────────────────
    UdpClientHelper clientH (ifaces.GetAddress (dstIdx), DATA_PORT);
    clientH.SetAttribute ("MaxPackets", UintegerValue (0xFFFFFFFFU));
    clientH.SetAttribute ("Interval",   TimeValue (Seconds (PACKET_INTERVAL)));
    clientH.SetAttribute ("PacketSize", UintegerValue (PACKET_SIZE));

    ApplicationContainer srcApp = clientH.Install (nodes.Get (srcIdx));
    srcApp.Start (Seconds (APP_START));
    srcApp.Stop  (Seconds (APP_STOP));

    UdpServerHelper serverH (DATA_PORT);
    ApplicationContainer dstApp = serverH.Install (nodes.Get (dstIdx));
    dstApp.Start (Seconds (0.0));
    dstApp.Stop  (Seconds (SIM_TIME));

    // App-layer Tx/Rx callbacks
    DynamicCast<UdpClient> (srcApp.Get (0))
        ->TraceConnectWithoutContext ("Tx", MakeBoundCallback (&TxCb, srcIdx));
    DynamicCast<UdpServer> (dstApp.Get (0))
        ->TraceConnectWithoutContext ("Rx", MakeBoundCallback (&RxCb, dstIdx));

    // ── FlowMonitor ───────────────────────────────────────────
    Ptr<FlowMonitor>        flowMon;
    Ptr<Ipv4FlowClassifier> classifier;

#if ENABLE_FLOWMON
    FlowMonitorHelper fmH;
    flowMon    = fmH.InstallAll ();
    classifier = DynamicCast<Ipv4FlowClassifier> (fmH.GetClassifier ());
#endif

    // ── PCAP ──────────────────────────────────────────────────
#if ENABLE_PCAP
    phy.EnablePcapAll (std::string (OUTPUT_PREFIX)
                       + "-run" + std::to_string (runId));
#endif

    // ── Run ───────────────────────────────────────────────────
    Simulator::Stop (Seconds (SIM_TIME));
    Simulator::Run ();

    // ==========================================================
    //  POST-RUN: FlowMonitor
    // ==========================================================
#if ENABLE_FLOWMON
    flowMon->CheckForLostPackets ();
    flowMon->SerializeToXmlFile (
        std::string (OUTPUT_PREFIX) + "-run" + std::to_string (runId)
        + "-flowmon.xml", true, true);

    double dur = APP_STOP - APP_START;
    auto   fs  = flowMon->GetFlowStats ();

    std::cout << "\n[Run " << runId << "] nodes=" << numNodes
              << " gap=" << gap << "m\n"
              << std::string (90, '-') << "\n"
              << std::left
              << std::setw(5)  << "FID"
              << std::setw(22) << "Src->Dst"
              << std::setw(7)  << "TxPkt"
              << std::setw(7)  << "RxPkt"
              << std::setw(7)  << "PDR%"
              << std::setw(10) << "Dly(ms)"
              << std::setw(10) << "Jit(ms)"
              << std::setw(12) << "Tput(kbps)"
              << "\n";

    for (auto &kv : fs) {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (kv.first);
        auto &s = kv.second;
        double pdr  = s.txPackets ? 100.0*s.rxPackets/s.txPackets : 0;
        double dly  = s.rxPackets ?
                      s.delaySum.GetSeconds ()*1000.0/s.rxPackets : 0;
        double jit  = (s.rxPackets > 1) ?
                      s.jitterSum.GetSeconds ()*1000.0/(s.rxPackets-1) : 0;
        double tput = s.rxBytes * 8.0 / dur / 1000.0;

        std::cout << std::left << std::fixed << std::setprecision (2)
                  << std::setw(5)  << kv.first
                  << std::setw(22) << (Ip2Str(t.sourceAddress) + "->"
                                       + Ip2Str(t.destinationAddress))
                  << std::setw(7)  << s.txPackets
                  << std::setw(7)  << s.rxPackets
                  << std::setw(7)  << pdr
                  << std::setw(10) << dly
                  << std::setw(10) << jit
                  << std::setw(12) << tput
                  << "\n";
    }
#endif

    // ==========================================================
    //  POST-RUN: App-layer CSV
    // ==========================================================
    {
        AppStats &tx = g_tx[srcIdx];
        AppStats &rx = g_rx[dstIdx];
        double pdr  = tx.txPkts ? 100.0*rx.rxPkts/tx.txPkts : 0;
        double adly = rx.rxPkts ? rx.sumDelay/rx.rxPkts*1000.0 : 0;
        double ajit = rx.rxPkts > 1 ? rx.sumJit/(rx.rxPkts-1)*1000.0 : 0;
        double tput = rx.rxBytes*8.0/(APP_STOP-APP_START)/1000.0;

        appLog << runId    << "," << numNodes << "," << gap    << ","
               << tx.txPkts << "," << rx.rxPkts << ","
               << std::fixed << std::setprecision (2)
               << pdr  << "," << adly << "," << ajit << "," << tput << "\n";
        appLog.flush ();
    }

    // ==========================================================
    //  POST-RUN: Routing-stats CSV
    // ==========================================================
    {
        AppStats &rx = g_rx[dstIdx];

        double avgHop = g_rstat.hopCnt ?
                        (double)g_rstat.hopSum / g_rstat.hopCnt : 0.0;
        double avgTTL = g_rstat.hopCnt ?
                        (double)g_rstat.ttlSum / g_rstat.hopCnt : 0.0;
        uint32_t minHop = g_rstat.hopCnt ? g_rstat.hopMin : 0;

        // Route Discovery Time (ms): first Rx - first Tx
        double rdt_ms = (g_rstat.firstRxT >= 0 && g_rstat.firstTxT >= 0)
                        ? (g_rstat.firstRxT - g_rstat.firstTxT) * 1000.0
                        : -1.0;

        // Normalized Routing Load: control packets / received data packets
        double nrl = rx.rxPkts > 0
                     ? (double)g_rstat.ctrlIpTx / rx.rxPkts
                     : 0.0;

        // Routing overhead as % of total IP traffic (bytes)
        double rohPct = g_rstat.totalIpB > 0
                        ? 100.0 * g_rstat.ctrlIpB / g_rstat.totalIpB
                        : 0.0;

        std::cout << "\n  [Routing] avgHop=" << avgHop
                  << " minHop=" << minHop
                  << " maxHop=" << g_rstat.hopMax
                  << " avgTTL=" << avgTTL
                  << " RDT="    << rdt_ms << "ms"
                  << " ctrlPkts=" << g_rstat.ctrlIpTx
                  << " NRL="    << nrl
                  << " overhead=" << rohPct << "%\n";

        routingLog << std::fixed << std::setprecision (3)
                   << runId              << ","
                   << numNodes          << ","
                   << gap               << ","
                   << avgHop            << ","
                   << minHop            << ","
                   << g_rstat.hopMax    << ","
                   << avgTTL            << ","
                   << rdt_ms            << ","
                   << g_rstat.totalIpTx << ","
                   << g_rstat.dataIpTx  << ","
                   << g_rstat.ctrlIpTx  << ","
                   << nrl               << ","
                   << g_rstat.ctrlIpB   << ","
                   << rohPct            << "\n";
        routingLog.flush ();
    }

    Simulator::Destroy ();
}

// =============================================================
//  MAIN
// =============================================================

int main (int argc, char *argv[])
{
    RngSeedManager::SetSeed (42);

    std::ofstream appLog (APP_LOG_FILE);
    appLog << "RunID,NumNodes,Gap,TxPkts,RxPkts,PDR%,"
              "AppDelay_ms,AppJitter_ms,AppTput_kbps\n";

    std::ofstream routingLog (ROUTING_LOG_FILE);
    routingLog << "RunID,NumNodes,Gap,"
                  "AvgHop,MinHop,MaxHop,AvgTTL,"
                  "RDT_ms,"
                  "TotalIpTx,DataIpTx,CtrlIpTx,"
                  "NRL,CtrlBytes,OverheadPct\n";

    int    runId    = 0;
    int    numNodes = NUM_NODES;
    double speed    = (NODE_SPEED_MIN + NODE_SPEED_MAX) / 2.0;
    double gap      = INTER_NODE_GAP;

    for (double sv = SWEEP_START;
         sv <= (double)SWEEP_END + 1e-9;
         sv += SWEEP_STEP, ++runId)
    {
#if SWEEP_PARAM == 1
        numNodes = (int)sv;
        if (numNodes < 2) numNodes = 2;
#elif SWEEP_PARAM == 2
        speed = sv;
#elif SWEEP_PARAM == 3
        gap = sv;
        if (gap < 1.0) gap = 1.0;
#endif

        std::cout << "\n==============================\n"
                  << " RUN " << runId << "  sweep_val=" << sv
                  << "\n==============================\n";

        RunOnce (runId, numNodes, speed, gap, appLog, routingLog);
    }

    appLog.close ();
    routingLog.close ();
    std::cout << "\nDone.\n  App CSV     : " << APP_LOG_FILE
              << "\n  Routing CSV : " << ROUTING_LOG_FILE << "\n";
    return 0;
}
