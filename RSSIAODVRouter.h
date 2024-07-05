#pragma once

#include "PacketHistory.h"
#include "Router.h"
#include <map>

/**
 * This is a mixin that extends Router with the ability to do Naive Flooding (in the standard mesh protocol sense)
 *
 *   Rules for broadcasting (listing here for now, will move elsewhere eventually):

  If to==BROADCAST and id==0, this is a simple broadcast (0 hops).  It will be
  sent only by the current node and other nodes will not attempt to rebroadcast
  it.

  If to==BROADCAST and id!=0, this is a "naive flooding" broadcast.  The initial
  node will send it on all local interfaces.

  When other nodes receive this message, they will
  first check if their recentBroadcasts table contains the (from, id) pair that
  indicates this message.  If so, we've already seen it - so we discard it.  If
  not, we add it to the table and then resend this message on all interfaces.
  When resending we are careful to use the "from" ID of the original sender. Not
  our own ID.  When resending we pick a random delay between 0 and 10 seconds to
  decrease the chance of collisions with transmitters we can not even hear.

  Any entries in recentBroadcasts that are older than X seconds (longer than the
  max time a flood can take) will be discarded.
 */

struct RoutingTableEntry {
    NodeNum destination;       // Destination node ID
    NodeNum next_hop;           // Next hop node ID to reach destination
    int hopCount;              // Number of hops to reach destination
    int seqNum;                // Sequence number (for AODV)
    int rssi;                  // RSSI value for the route
    time_t lifetime;           // Time the route is valid (optional)
};

class RSSIAODVRouter : public Router, protected PacketHistory
{
  private:
  std::map<uint32_t, RoutingTableEntry> rebroadcastRoutingTable;
  std::map<uint32_t, RoutingTableEntry> ackRoutingTable;
  int mySeqNum;

  public:
    /**
     * Constructor
     *
     */
    RSSIAODVRouter();

    /**
     * Send a packet on a suitable interface.  This routine will
     * later free() the packet to pool.  This routine is not allowed to stall.
     * If the txmit queue is full it might return an error
     */
    virtual ErrorCode send(meshtastic_MeshPacket *p) override;

  protected:
    /**
     * Should this incoming filter be dropped?
     *
     * Called immediately on reception, before any further processing.
     * @return true to abandon the packet
     */
    virtual bool shouldFilterReceived(const meshtastic_MeshPacket *p) override;

    /**
     * Look for broadcasts we need to rebroadcast
     */
    virtual void sniffReceived(const meshtastic_MeshPacket *p, const meshtastic_Routing *c) override;
    bool isInRebroadcastRoutingTable(NodeNum destination, int rssiThreshold);
    bool forRREP(const meshtastic_MeshPacket *p);
    bool forRREQ(const meshtastic_MeshPacket *p);
    void updateAckRoutingTable(const meshtastic_MeshPacket *p, int rssi);
    void updateRebroadcastRoutingTable(uint32_t neighborId, int rssi);
    void sendRREP(NodeNum destination, int rssi, const meshtastic_MeshPacket *originalRREQ);
    void rebroadcastRREQToNeighborsWithSufficientRSSI(const meshtastic_MeshPacket *p);
    void printRebroadcastRoutingTable();
    void printAckRoutingTable();
};