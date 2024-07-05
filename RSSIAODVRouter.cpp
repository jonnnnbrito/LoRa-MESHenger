#include "RSSIAODVRouter.h"
#include "configuration.h"
#include "mesh-pb-constants.h"

RSSIAODVRouter::RSSIAODVRouter() {
    mySeqNum = 1;
}

/**
 * Send a packet on a suitable interface.  This routine will
 * later free() the packet to pool.  This routine is not allowed to stall.
 * If the txmit queue is full it might return an error
 */
ErrorCode RSSIAODVRouter::send(meshtastic_MeshPacket *p)
{
    // Add any messages _we_ send to the seen message list (so we will ignore all retransmissions we see)
    wasSeenRecently(p); // FIXME, move this to a sniffSent method

    return Router::send(p);
}

bool RSSIAODVRouter::shouldFilterReceived(const meshtastic_MeshPacket *p)
{
    if (wasSeenRecently(p)) { // Note: this will also add a recent packet record
        printPacket("Ignoring incoming msg, because we've already seen it", p);
        if (config.device.role != meshtastic_Config_DeviceConfig_Role_ROUTER &&
            config.device.role != meshtastic_Config_DeviceConfig_Role_ROUTER_CLIENT &&
            config.device.role != meshtastic_Config_DeviceConfig_Role_REPEATER) {
            // cancel rebroadcast of this message *if* there was already one, unless we're a router/repeater!
            Router::cancelSending(p->from, p->id);
        }
        return true;
    }

    return Router::shouldFilterReceived(p);
}

void RSSIAODVRouter::sniffReceived(const meshtastic_MeshPacket *p, const meshtastic_Routing *c) {
    printPacket("What is this packet? ----------", p);

    int rssi = p->rx_rssi; 
    LOG_DEBUG("[RSSI-AODV] ----- rxRSSI = %d\n", rssi);

    // 1. NeighborInfo Packet Handling (Always Process First)
    if (p->decoded.portnum == meshtastic_PortNum_NEIGHBORINFO_APP && rssi != 0) { 
        uint32_t neighborId = p->from;
        updateRebroadcastRoutingTable(neighborId, rssi);
        printRebroadcastRoutingTable();
    }

    // 2. RREQ Handling (Only if not the originator)
    if (forRREP(p)) {

        if (p->from != getNodeNum()) { 
            updateAckRoutingTable(p, p->rx_rssi);
            printAckRoutingTable();
            sendRREP(p->from, p->rx_rssi, p);  // Send RREP back to source
            LOG_DEBUG("[RSSI-AODV RREP] ----- RREP received at node 0x%x from node 0x%x (RSSI: %d)\n", getNodeNum(), p->from, p->rx_rssi);
            
        }
        
    } else if (forRREQ(p)) {
        
        updateRebroadcastRoutingTable(p->from, p->rx_rssi);
        // Check if the RREQ is meant for us
        if (getNodeNum() == p->to) { // Check if I'm the destination of the RREQ
            LOG_DEBUG("[RSSI-AODV RREQ] ----- Received RREQ from node 0x%x (RSSI: %d)\n", p->from, p->rx_rssi);
        }

        if (isInRebroadcastRoutingTable(p->to, p->rx_rssi)) {
            // Send RREP back to the source node (since we already have a route)
            sendRREP(p->from, p->rx_rssi, p); 

        } else {
            ++mySeqNum;
            if (p->hop_limit > 0) {
                updateRebroadcastRoutingTable(p->from, p->rx_rssi);
                rebroadcastRREQToNeighborsWithSufficientRSSI(p);
            } else {
                LOG_DEBUG("[RSSI-AODV RREQ] ----- Hop limit reached zero (initial broadcast). RREQ will be rebroadcast with default hop limit.\n");
            }
        }
    }
    // handle the packet as normal
    Router::sniffReceived(p, c);
}

bool RSSIAODVRouter::isInRebroadcastRoutingTable(NodeNum destination, int rssiThreshold) {
    auto it = rebroadcastRoutingTable.find(destination);
    return (it != rebroadcastRoutingTable.end() && (it->second.rssi >= rssiThreshold && it->second.rssi <= -1));
}

bool RSSIAODVRouter::forRREP(const meshtastic_MeshPacket *p) {
    return (p->to == NODENUM_BROADCAST &&               // Check if it's a broadcast
            p->from != 0 &&                          // Check for non-zero 'from' address
            p->hop_limit != 0 &&                      // Check for non-zero hop limit
            p->which_payload_variant == meshtastic_MeshPacket_decoded_tag &&  // Check if it has a decoded payload
            p->decoded.portnum == 1);                 // Check for portnum 1 (user/AODV message)
}

bool RSSIAODVRouter::forRREQ(const meshtastic_MeshPacket *p) {
    return (p->to == NODENUM_BROADCAST &&               // Check if it's a broadcast
            p->from != getNodeNum() &&                 // Check if it's NOT from ourselves
            p->which_payload_variant == meshtastic_MeshPacket_decoded_tag);  // Check if it has a decoded payload                       // Check if the message wants an ACK (RREQs typically do)
}

void RSSIAODVRouter::updateAckRoutingTable(const meshtastic_MeshPacket *p, int rssi) {
    int rssiThreshold = -80; // Example threshold, adjust as needed
    
    NodeNum source_node = p->from; // The node that sent the RREP (source of the route)
    NodeNum next_hop = p->from;    // Next hop to reach the source_node
    int hopCount = p->hop_limit;   // Use hop_limit as hop count

    // Exclude self from the acknowledgment table
    if (source_node == getNodeNum()) {
        LOG_DEBUG("[RSSI-AODV RREP] ----- Skipping update: Received RREP from myself.\n"); // Optional log for debugging
        return; 
    }

    // Check if an entry for the source_node exists
    auto it = ackRoutingTable.find(source_node);
    if (it != ackRoutingTable.end()) {
        // Entry exists, update if the new RREP has a higher RSSI
        if (rssi >= rssiThreshold && rssi <= -1) { // Compare RSSI values
            it->second.next_hop = next_hop;
            it->second.rssi = rssi;
            // Optional: Update other fields (e.g., hop_count) if needed 
        } else {
            // Remove entry if RSSI is outside the range
            LOG_DEBUG("[RSSI-AODV RREP] ----- Removing sourceNode 0x%x from ackRoutingTable (RSSI out of range: %d)\n", source_node, rssi);
            ackRoutingTable.erase(it);
        }
    } else {
        // No existing entry, create a new one
        ackRoutingTable[source_node] = {source_node, next_hop, hopCount, this->mySeqNum, rssi}; // Add to the routing table
        LOG_DEBUG("[RSSI-AODV RREP] ----- New Ack Routing Table Entry Created for source_node: 0x%x, next_hop: 0x%x, RSSI: %d\n", source_node, next_hop, rssi);
    }
}

void RSSIAODVRouter::updateRebroadcastRoutingTable(uint32_t neighbor_node, int rssi) {
    int rssiThreshold = -80; // Example threshold, adjust as needed
    
    // Check if an entry for the neighbor_node already exists
    auto it = rebroadcastRoutingTable.find(neighbor_node);
    if (it != rebroadcastRoutingTable.end()) {
        // Entry exists, update if the new RSSI is higher
        if (rssi >= rssiThreshold && rssi <= -1) {
            it->second.rssi = rssi;
        } else {
            // Remove entry if RSSI is outside the range
            LOG_DEBUG("[RSSI-AODV HELLO] ----- Removing sourceNode 0x%x from ackRoutingTable (RSSI out of range: %d)\n", neighbor_node, rssi);
            rebroadcastRoutingTable.erase(it);
        }
    } else {
        // No existing entry, create a new one
        rebroadcastRoutingTable[neighbor_node] = {neighbor_node, 0, 0, 0, rssi, 0}; // Placeholder for other fields
        LOG_DEBUG("[RSSI-AODV HELLO] ----- New Rebroadcast Routing Table Entry Created for neighborNode: 0x%x, RSSI: %d\n", neighbor_node, rssi);
    }
}

void RSSIAODVRouter::sendRREP(NodeNum destination, int rssi, const meshtastic_MeshPacket *originalRREQ) {
    // Create a copy of the original RREQ packet to use as the RREP
    meshtastic_MeshPacket *rrepPacket = packetPool.allocCopy(*originalRREQ); // copy of RREQ

    int rssiThreshold = -80;
    // Check if the RSSI is within the acceptable range
    if (rssi <= rssiThreshold && rssi <= -1) {
        LOG_DEBUG("[RSSI-AODV RREP] ----- Not sending RREP to sourceNode 0x%x (RSSI out of range: %d)\n", destination, rssi);
        return;  // Don't send the RREP if RSSI is outside the range
    }

    // Modify the RREP packet
    rrepPacket->to = destination;       // Destination is the source of the RREQ
    rrepPacket->from = getNodeNum();    // Source is the current node
    rrepPacket->want_ack = false;       // RREPs don't need explicit ACKs
    rrepPacket->hop_limit--;           // Decrement the hop limit (like in flooding)

    // Customize the RREP message
    std::string rrepMessage = "[RSSI-AODV RREP] ----- RREP received from Node 0x" 
                          + std::string(String(getNodeNum(), HEX).c_str()) 
                          + " with RSSI: " + std::to_string(rssi);
    rrepPacket->decoded.payload.size = rrepMessage.length();
    memcpy(rrepPacket->decoded.payload.bytes, rrepMessage.c_str(), rrepMessage.length());

    // Log the RREP for debugging
    LOG_DEBUG("[RSSI-AODV RREP] ----- Node 0x%x will send RREP back to source node 0x%x (RSSI: %d)\n", getNodeNum(), destination, rssi);

    // Send the RREP
    Router::send(rrepPacket);           // No need to specify destination here
}

void RSSIAODVRouter::rebroadcastRREQToNeighborsWithSufficientRSSI(const meshtastic_MeshPacket *p) {
    int rssiThreshold = -80; // Example threshold, adjust as needed

    for (const auto& entry : rebroadcastRoutingTable) { 
        NodeNum neighborId = entry.first; 
        int neighborRSSI = entry.second.rssi; 

        // Exclude original sender and self (RSSI 0)
        if (neighborId != p->from && neighborId != getNodeNum() && neighborRSSI != 0) {

            int rssiThreshold = -80;
            // Check if the RSSI is within the acceptable range
            if (p->rx_rssi <= rssiThreshold && p->rx_rssi <= -1) {
                LOG_DEBUG("[RSSI-AODV RREQ] ----- Not sending RREQ/Message to Node 0x%x (RSSI out of range: %d)\n", p->to, p->rx_rssi);
                return;  // Don't send the RREP if RSSI is outside the range
            }
            
            // Check if neighbor's RSSI is within the acceptable range (-50 >= RSSI >= -1)
            if (neighborRSSI >= rssiThreshold && neighborRSSI <= -1) { // Corrected comparison
                meshtastic_MeshPacket *rreqToRebroadcast = packetPool.allocCopy(*p);
                rreqToRebroadcast->hop_limit--;

                LOG_DEBUG("[RSSI-AODV RREQ] ----- Rebroadcasting RREQ (id=0x%x) to neighbor 0x%x (RSSI: %d)\n", p->id, neighborId, neighborRSSI);
                Router::send(rreqToRebroadcast); 
            } else {
                LOG_DEBUG("[RSSI-AODV RREQ] ----- Not rebroadcasting to neighbor 0x%x (RSSI out of range: %d)\n", neighborId, neighborRSSI);
                return;
            }
        }
    }
}

void RSSIAODVRouter::printRebroadcastRoutingTable() {
    int rssiThreshold = -50;
    LOG_DEBUG("[RSSI-AODV HELLO] ----- Rebroadcast Routing Table:\n");
    for (const auto& entry : rebroadcastRoutingTable) {
        if (entry.second.rssi >= rssiThreshold && entry.second.rssi <= -1) {
            LOG_DEBUG("[RSSI-AODV HELLO] -----   Node 0x%x (RSSI: %d)\n", entry.first, entry.second.rssi);
        }
    }
}

void RSSIAODVRouter::printAckRoutingTable() {
    int rssiThreshold = -50;
    LOG_DEBUG("[RSSI-AODV RREP] ----- Ack Routing Table:\n");
    for (const auto& entry : ackRoutingTable) {
        if (entry.second.rssi >= rssiThreshold && entry.second.rssi <= -1) {
            LOG_DEBUG("  Source Node: 0x%x, Next Hop: 0x%x, RSSI: %d\n", entry.first, entry.second.next_hop, entry.second.rssi);
        }
    }
}