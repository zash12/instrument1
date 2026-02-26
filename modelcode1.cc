/* =============================================================
 *  manet-metrics.cc  –  NS3 3.39
 *  Metrics: PDR | E2E Delay | Jitter | Throughput
 *  Layers : App (SeqTs) | FlowMonitor (IP) | PCAP (L2)
 * ============================================================= */

// ─────────────────────────────────────────────────────────────
//  ROUTING  ── choose ONE: 1=AODV  2=OLSR  3=DSR  4=DSDV
// ─────────────────────────────────────────────────────────────
#define ROUTING_PROTOCOL   1

// ─────────────────────────────────────────────────────────────
//  TOPOLOGY
//    GRID_TYPE  1 = 1-D row   2 = 2-D grid
//    INTER_NODE_GAP  metres between adjacent nodes
// ─────────────────────────────────────────────────────────────
#define GRID_TYPE          2
#define INTER_NODE_GAP     50.0

// ─────────────────────────────────────────────────────────────
//  MOBILITY
//    1 = RandomWaypoint   2 = ConstantPosition   3 = GaussMarkov
// ─────────────────────────────────────────────────────────────
#define MOBILITY_MODEL     2
#define NODE_SPEED_MIN     1.0
#define NODE_SPEED_MAX     20.0
#define NODE_PAUSE_MIN     0.0
#define NODE_PAUSE_MAX     2.0

// ─────────────────────────────────────────────────────────────
//  FIXED SIMULATION PARAMETERS
// ─────────────────────────────────────────────────────────────
#define NUM_NODES          10
#define SIM_TIME           30.0
#define PACKET_SIZE        512
#define PACKET_INTERVAL    0.1
#define APP_START          1.0
#define APP_STOP           29.0
#define TX_POWER_DBM       20.0

// ─────────────────────────────────────────────────────────────
//  SWEEP CONTROL
//    SWEEP_PARAM  0=none  1=NumNodes  2=Speed  3=Gap
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

// =============================================================
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/seq-ts-header.h"

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
#include <iomanip>          // setw, setprecision, fixed, left
#include <cmath>
#include <map>
#include <string>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE ("ManetMetrics");

// ─────────────────────────────────────────────────────────────
//  App-layer per-node counters
// ─────────────────────────────────────────────────────────────
struct AppStats {
    uint32_t txPkts   = 0;
    uint32_t rxPkts   = 0;
    double   rxBytes  = 0;
    double   sumDelay = 0;    // seconds
    double   sumJit   = 0;    // |d_i - d_{i-1}|  seconds
    double   lastDly  = -1.0;
};

// Globals (reset each RunOnce call)
static std::map<uint32_t, AppStats> g_rx;
static std::map<uint32_t, AppStats> g_tx;

// ─────────────────────────────────────────────────────────────
//  PLAIN static callback functions (MakeBoundCallback requires
//  ordinary function pointers, NOT lambdas)
// ─────────────────────────────────────────────────────────────

// Tx: UdpClient fires (Ptr<const Packet>)
// First bound arg carries the source node index
static void TxCb (uint32_t srcIdx, Ptr<const Packet> pkt)
{
    g_tx[srcIdx].txPkts++;
}

// Rx: UdpServer fires (Ptr<const Packet>)
// Extract send-timestamp from SeqTsHeader embedded by UdpClient
// First bound arg carries the destination node index
static void RxCb (uint32_t dstIdx, Ptr<const Packet> pkt)
{
    SeqTsHeader hdr;
    Ptr<Packet> cp = pkt->Copy();
    cp->RemoveHeader(hdr);

    double txT  = hdr.GetTs().GetSeconds();
    double rxT  = Simulator::Now().GetSeconds();
    double dly  = rxT - txT;
    if (dly < 0) dly = 0;

    AppStats &s = g_rx[dstIdx];
    s.rxPkts++;
    s.rxBytes += (double)pkt->GetSize();
    s.sumDelay += dly;
    if (s.lastDly >= 0) s.sumJit += std::fabs(dly - s.lastDly);
    s.lastDly = dly;
}

// ─────────────────────────────────────────────────────────────
//  Place nodes on 1-D or 2-D fixed grid, then apply mobility
// ─────────────────────────────────────────────────────────────
static void PlaceGrid (NodeContainer &nodes, int n, double gap)
{
    Ptr<ListPositionAllocator> pos = CreateObject<ListPositionAllocator>();

#if GRID_TYPE == 1
    for (int i = 0; i < n; i++)
        pos->Add(Vector(i * gap, 0.0, 0.0));
#else
    int cols = (int)std::ceil(std::sqrt((double)n));
    for (int i = 0; i < n; i++)
        pos->Add(Vector((i % cols) * gap, (i / cols) * gap, 0.0));
#endif

    MobilityHelper mob;
    mob.SetPositionAllocator(pos);

#if MOBILITY_MODEL == 1
    // ── Random Waypoint ──────────────────────────────────────
    double area = n * gap * 1.5;
    std::ostringstream speedStr, pauseStr, rectStr;
    speedStr << "ns3::UniformRandomVariable[Min="
             << NODE_SPEED_MIN << "|Max=" << NODE_SPEED_MAX << "]";
    pauseStr << "ns3::UniformRandomVariable[Min="
             << NODE_PAUSE_MIN << "|Max=" << NODE_PAUSE_MAX << "]";
    rectStr  << "ns3::RandomRectanglePositionAllocator";

    Ptr<RandomRectanglePositionAllocator> rpa =
        CreateObject<RandomRectanglePositionAllocator>();
    rpa->SetAttribute("X", StringValue(
        "ns3::UniformRandomVariable[Min=0|Max=" + std::to_string(area) + "]"));
    rpa->SetAttribute("Y", StringValue(
        "ns3::UniformRandomVariable[Min=0|Max=" + std::to_string(area) + "]"));

    mob.SetMobilityModel(
        "ns3::RandomWaypointMobilityModel",
        "Speed",              StringValue(speedStr.str()),
        "Pause",              StringValue(pauseStr.str()),
        "PositionAllocator",  PointerValue(rpa));

#elif MOBILITY_MODEL == 2
    // ── Static ───────────────────────────────────────────────
    mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");

#elif MOBILITY_MODEL == 3
    // ── Gauss-Markov ─────────────────────────────────────────
    {
    double area = n * gap * 1.5;
    std::ostringstream vStr;
    vStr << "ns3::UniformRandomVariable[Min="
         << NODE_SPEED_MIN << "|Max=" << NODE_SPEED_MAX << "]";
    mob.SetMobilityModel(
        "ns3::GaussMarkovMobilityModel",
        "Bounds",          BoxValue(Box(0, area, 0, area, 0, 0)),
        "TimeStep",        TimeValue(Seconds(0.5)),
        "Alpha",           DoubleValue(0.85),
        "MeanVelocity",    StringValue(vStr.str()),
        "MeanDirection",   StringValue("ns3::UniformRandomVariable[Min=0|Max=6.283185]"),
        "MeanPitch",       StringValue("ns3::UniformRandomVariable[Min=0.05|Max=0.05]"));
    }
#else
    #error "MOBILITY_MODEL must be 1 2 or 3"
#endif

    mob.Install(nodes);
}

// ─────────────────────────────────────────────────────────────
//  Helper: Ipv4Address → string  (NS3 has no .toString())
// ─────────────────────────────────────────────────────────────
static std::string Ip2Str (Ipv4Address a)
{
    std::ostringstream os;
    a.Print(os);
    return os.str();
}

// ─────────────────────────────────────────────────────────────
//  Single simulation run
// ─────────────────────────────────────────────────────────────
static void RunOnce (int runId, int numNodes, double /*speed*/, double gap,
                     std::ofstream &appLog)
{
    g_rx.clear();
    g_tx.clear();

    // ── Nodes ─────────────────────────────────────────────────
    NodeContainer nodes;
    nodes.Create(numNodes);

    // ── WiFi ad-hoc ───────────────────────────────────────────
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",    StringValue("DsssRate11Mbps"),
                                 "ControlMode", StringValue("DsssRate1Mbps"));

    YansWifiPhyHelper phy;
    phy.Set("TxPowerStart", DoubleValue(TX_POWER_DBM));
    phy.Set("TxPowerEnd",   DoubleValue(TX_POWER_DBM));
    YansWifiChannelHelper ch = YansWifiChannelHelper::Default();
    phy.SetChannel(ch.Create());

    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");

    NetDeviceContainer devs = wifi.Install(phy, mac, nodes);

    // ── Mobility ──────────────────────────────────────────────
    PlaceGrid(nodes, numNodes, gap);

    // ── Internet Stack + Routing ──────────────────────────────
    InternetStackHelper internet;

#if ROUTING_PROTOCOL == 1
    { AodvHelper r; internet.SetRoutingHelper(r); internet.Install(nodes); }
#elif ROUTING_PROTOCOL == 2
    { OlsrHelper r; internet.SetRoutingHelper(r); internet.Install(nodes); }
#elif ROUTING_PROTOCOL == 3
    {
        DsrHelper      dsr;
        DsrMainHelper  dsrMain;
        internet.Install(nodes);
        dsrMain.Install(dsr, nodes);
    }
#elif ROUTING_PROTOCOL == 4
    { DsdvHelper r; internet.SetRoutingHelper(r); internet.Install(nodes); }
#endif

    // ── IP Addresses ──────────────────────────────────────────
    Ipv4AddressHelper addrH;
    addrH.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = addrH.Assign(devs);

    // ── Applications ──────────────────────────────────────────
    uint16_t port   = 9;
    uint32_t srcIdx = 0;
    uint32_t dstIdx = (uint32_t)(numNodes - 1);

    // UdpClient → UdpServer (SeqTsHeader is added automatically by UdpClient)
    UdpClientHelper clientH(ifaces.GetAddress(dstIdx), port);
    clientH.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFFU));
    clientH.SetAttribute("Interval",   TimeValue(Seconds(PACKET_INTERVAL)));
    clientH.SetAttribute("PacketSize", UintegerValue(PACKET_SIZE));

    ApplicationContainer srcApp = clientH.Install(nodes.Get(srcIdx));
    srcApp.Start(Seconds(APP_START));
    srcApp.Stop(Seconds(APP_STOP));

    UdpServerHelper serverH(port);
    ApplicationContainer dstApp = serverH.Install(nodes.Get(dstIdx));
    dstApp.Start(Seconds(0.0));
    dstApp.Stop(Seconds(SIM_TIME));

    // ── Connect trace callbacks (plain function pointers) ──────
    Ptr<UdpClient> cli = DynamicCast<UdpClient>(srcApp.Get(0));
    cli->TraceConnectWithoutContext(
        "Tx", MakeBoundCallback(&TxCb, srcIdx));

    Ptr<UdpServer> srv = DynamicCast<UdpServer>(dstApp.Get(0));
    srv->TraceConnectWithoutContext(
        "Rx", MakeBoundCallback(&RxCb, dstIdx));

    // ── FlowMonitor ───────────────────────────────────────────
    Ptr<FlowMonitor>         flowMon;
    Ptr<Ipv4FlowClassifier>  classifier;

#if ENABLE_FLOWMON
    FlowMonitorHelper fmH;
    flowMon    = fmH.InstallAll();
    classifier = DynamicCast<Ipv4FlowClassifier>(fmH.GetClassifier());
#endif

    // ── PCAP ──────────────────────────────────────────────────
#if ENABLE_PCAP
    {
        std::string pfx = std::string(OUTPUT_PREFIX)
                        + "-run" + std::to_string(runId);
        phy.EnablePcapAll(pfx);
    }
#endif

    // ── Run ───────────────────────────────────────────────────
    Simulator::Stop(Seconds(SIM_TIME));
    Simulator::Run();

    // ══════════════════════════════════════════════════════════
    //  FlowMonitor post-processing
    // ══════════════════════════════════════════════════════════
#if ENABLE_FLOWMON
    flowMon->CheckForLostPackets();
    {
        std::string xmlFile = std::string(OUTPUT_PREFIX)
                            + "-run" + std::to_string(runId)
                            + "-flowmon.xml";
        flowMon->SerializeToXmlFile(xmlFile, true, true);

        double dur = APP_STOP - APP_START;
        auto   fs  = flowMon->GetFlowStats();

        std::cout << "\n[Run " << runId
                  << "]  nodes=" << numNodes
                  << "  gap=" << gap << "m\n"
                  << std::string(78, '-') << "\n"
                  << std::left
                  << std::setw(5)  << "FID"
                  << std::setw(24) << "Src->Dst"
                  << std::setw(8)  << "TxPkts"
                  << std::setw(8)  << "RxPkts"
                  << std::setw(8)  << "PDR%"
                  << std::setw(12) << "Dly(ms)"
                  << std::setw(12) << "Jit(ms)"
                  << std::setw(12) << "Tput(kbps)"
                  << "\n";

        for (auto &kv : fs) {
            Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(kv.first);
            auto &s = kv.second;

            double pdr  = s.txPackets ? 100.0*s.rxPackets/s.txPackets : 0;
            double dly  = s.rxPackets ?
                          s.delaySum.GetSeconds()*1000.0/s.rxPackets : 0;
            double jit  = (s.rxPackets > 1) ?
                          s.jitterSum.GetSeconds()*1000.0/(s.rxPackets-1) : 0;
            double tput = (s.rxBytes * 8.0) / dur / 1000.0;

            std::string flow = Ip2Str(t.sourceAddress) + "->"
                             + Ip2Str(t.destinationAddress);

            std::cout << std::left  << std::fixed << std::setprecision(2)
                      << std::setw(5)  << kv.first
                      << std::setw(24) << flow
                      << std::setw(8)  << s.txPackets
                      << std::setw(8)  << s.rxPackets
                      << std::setw(8)  << pdr
                      << std::setw(12) << dly
                      << std::setw(12) << jit
                      << std::setw(12) << tput
                      << "\n";
        }
    }
#endif

    // ══════════════════════════════════════════════════════════
    //  App-layer CSV row
    // ══════════════════════════════════════════════════════════
    {
        AppStats &tx = g_tx[srcIdx];
        AppStats &rx = g_rx[dstIdx];

        double pdr   = tx.txPkts ? 100.0*rx.rxPkts/tx.txPkts : 0;
        double adly  = rx.rxPkts ? rx.sumDelay/rx.rxPkts*1000.0 : 0;
        double ajit  = rx.rxPkts > 1 ? rx.sumJit/(rx.rxPkts-1)*1000.0 : 0;
        double tput  = rx.rxBytes*8.0/(APP_STOP-APP_START)/1000.0;

        appLog << runId    << ","
               << numNodes << ","
               << gap      << ","
               << tx.txPkts << ","
               << rx.rxPkts << ","
               << std::fixed << std::setprecision(2)
               << pdr  << ","
               << adly << ","
               << ajit << ","
               << tput << "\n";
        appLog.flush();
    }

    Simulator::Destroy();
}

// ─────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────
int main (int argc, char *argv[])
{
    RngSeedManager::SetSeed(42);

    std::ofstream appLog(APP_LOG_FILE);
    appLog << "RunID,NumNodes,Gap,TxPkts,RxPkts,PDR%,"
              "AppDelay_ms,AppJitter_ms,AppTput_kbps\n";

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
                  << " RUN " << runId
                  << "  sweep_val=" << sv << "\n"
                  << "==============================\n";

        RunOnce(runId, numNodes, speed, gap, appLog);
    }

    appLog.close();
    std::cout << "\nDone. CSV: " << APP_LOG_FILE << "\n";
    return 0;
}
