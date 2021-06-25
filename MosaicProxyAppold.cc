/*
 * Copyright (c) 2020 Fraunhofer FOKUS and others. All rights reserved.
 *
 * Contact: mosaic@fokus.fraunhofer.de
 *
 * This class is developed for the MOSAIC-NS-3 coupling.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "MosaicProxyApp.h"

#include "inet/applications/common/SocketTag_m.h"
#include "inet/common/Ptr.h"
#include "inet/common/packet/Message.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/packet/chunk/cPacketChunk.h"
#include "inet/transportlayer/common/L4PortTag_m.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "inet/physicallayer/ieee80211/packetlevel/Ieee80211ControlInfo_m.h"
#include "inet/physicallayer/contract/packetlevel/RadioControlInfo_m.h"
#include "inet/physicallayer/common/packetlevel/RadioMedium.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/physicallayer/contract/packetlevel/IRadio.h"
#include "inet/networklayer/common/L3Address.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/common/packet/recorder/PacketDump.h"
#include "inet/common/packet/recorder/PcapDump.h"

#include "msg/MosaicAppPacket_m.h"

namespace omnetpp_federate {

Define_Module(MosaicProxyApp);

void MosaicProxyApp::setExternalId(int id) {
    m_externalId = id;
}

int MosaicProxyApp::getExternalId() const {
    return m_externalId;
}

/**
 * Initialize method to bind a udp socket to this app layer.
 */
void MosaicProxyApp::initialize(int stage) {
    // because of IPAddressResolver, we need to wait until interfaces are registered,
    // address auto-assignment takes place etc.
    if (stage == 3) {
        EV << "Initializing MosaicUDPApp stage " << stage << std::endl;
        this->numInitStages();
        localPort = par("localPort");
        destPort = par("destPort");
        maxProcDelay = par("maxProcDelay");

        socket.setOutputGate(gate("socketOut"));
        const char *la = par("localAddress");
        localAddress = *la ? inet::L3AddressResolver().resolve(la) : inet::L3Address();
        socket.bind(localAddress, localPort);
        socket.setBroadcast(true);
    } else if (stage == 5) {
        /** find our radios and save the references */
        if (inet::IInterfaceTable* ift = inet::L3AddressResolver().interfaceTableOf(this->getParentModule())) {
            if (ift) {
                for (int i = 0; i < ift->getNumInterfaces(); i++) {
                    inet::InterfaceEntry *tmpIe = ift->getInterface(i);
                    if (tmpIe == nullptr || tmpIe->isLoopback()) {
                        continue;
                    }
                    if (!strncmp(tmpIe->getFullName(), "wlan0", 6)) {
                        ie0 = tmpIe;
                    } else if (!strncmp(tmpIe->getFullName(), "wlan1", 6)) {
                        ie1 = tmpIe;
                    }
                }
            }
        }
        if (ie0 == nullptr || ie1 == nullptr) {
            setOperationalState(NOT_OPERATING);
            return;
        }
        if ((radio0 = dynamic_cast<inet::physicallayer::Ieee80211Radio * >(ie0->getSubmodule("radio"))) == 0) {
            setOperationalState(NOT_OPERATING);
            return;
        }
        if ((radio1 = dynamic_cast<inet::physicallayer::Ieee80211Radio * >(ie1->getSubmodule("radio"))) == 0) {
            setOperationalState(NOT_OPERATING);
            return;
        }

        //Disconnect all radios
        numRadios = 2;
        connectRadios(0);
        setOperationalState(OPERATING);
    }
}

/**
 * Simulate processing delay on application layer to avoid problem of dcf in mac layer
 * with completely synchronous message sending.
 */
void MosaicProxyApp::sendDelayedToCoAP(omnetpp::cPacket *msg, int srcPort, const inet::Ipv4Address& destAddr, int destPort, double delay) {
    // send message to UDP, with the appropriate control info attached
    auto packet = omnetpp::check_and_cast<MosaicAppPacket*>(msg);

    if (numRadios < 1) {
        EV << "No radio turned on, discarding message " << packet->getMsgId() << std::endl;
        return;
    }

    // Create CoAP Packet containing {msg}
    auto className = msg->getClassName();
    auto *coapPacket = new inet::Packet(!strncmp("inet::", className, 6) ? className + 6 : className);
    coapPacket->insertAtBack(inet::makeShared<inet::cPacketChunk>(msg));
    auto addresses = coapPacket->addTagIfAbsent<inet::L3AddressReq>();
    addresses->setSrcAddress(localAddress);
    addresses->setDestAddress(destAddr);
    coapPacket->addTagIfAbsent<inet::SocketReq>()->setSocketId(socket.generateSocketId());
    coapPacket->addTagIfAbsent<inet::L4PortReq>()->setDestPort(destPort);
    
    // novo codigo
    //auto pcapUDP = new inet::PcapDump();
    //pcapUDP->openPcap("pcapUDP.pcap", 65535, 0);
    //pcapSend->writePacket(omnetpp::simtime_t(), coapPacket);
    EV << "Passei por aqui - sendDelayedToCoAP" << std::endl;
    //pcapUDP->closePcap();
    //


    int channelId = packet->getChannelId();
    if (numRadios > 0 && channelId == radio0Channel) {
        coapPacket->addTagIfAbsent<inet::InterfaceReq>()->setInterfaceId(ie0->getInterfaceId());
    } else if (numRadios > 1 && channelId == radio1Channel) {
        coapPacket->addTagIfAbsent<inet::InterfaceReq>()->setInterfaceId(ie1->getInterfaceId());
    } else {
        EV << "Unused channel set in Packet " << std::endl;
        return;
    }

    EV << "Enviando pacote do ID: " << packet->getMsgId() << " no canal " << packet->getChannelId() << std::endl;
    EV << "O delay do pacote CoAP foi: " << delay << " e a mensagem foi: " << "red" << std::endl;
    sendDelayed(coapPacket, delay, gate("socketOut"));
}

/**
 * Method for sending of unreliable udp packets,
 * triggered from MosaicScenarioManager and hence from Mosaic.
 */
void MosaicProxyApp::sendPacket(omnetpp::cMessage *msg) {
    EV << "MosaicUDP send packet" << std::endl;

    auto *packet = inet::check_and_cast<MosaicAppPacket *>(msg);
    auto destAddr = packet->getDestAddr();
    double delay = dblrand() * maxProcDelay * 4;
    
   // novo codigo
    //auto pcapSend = new inet::PcapDump();
    //pcapSend->openPcap("pcapSend.pcap", 65535, 0);
    //pcapSend->writePacket(omnetpp::simtime_t(), packet);
    EV << "Passei por aqui - sendPacket" << std::endl;
    //pcapSend->closePcap();
    //

    EV << "O delay do pacote normal foi: " << delay * 3 << " e a mensagem foi: " << " " << std::endl;
    sendDelayedToCoAP(omnetpp::check_and_cast<omnetpp::cPacket *>(msg->dup()), localPort, destAddr, destPort, delay);
}

/**
 * Receive of udp packets and forwarding to Mosaic applications.
 */
void MosaicProxyApp::receivePacket(omnetpp::cMessage *msg) {
    EV << "MosaicUDP received packet: ";

    auto udp_packet = inet::check_and_cast<inet::Packet*>(msg);
    auto cPacket = udp_packet->popAtBack<inet::cPacketChunk>().get()->getPacket();
    auto packet = omnetpp::check_and_cast<MosaicAppPacket*>(cPacket);
    EV << "MosaicUDP: srcNodeId " << packet->getNodeId() << ", msgId " << packet->getMsgId() << std::endl;
    packet->setNodeId(m_externalId);

    // novo codigo
     auto pcapSend = new inet::PcapDump();
     pcapSend->openPcap("pcapReceive.pcap", 65535, 0);
     pcapSend->writePacket(omnetpp::simtime_t(), cPacket);
     EV << "Passei por aqui - receivePacket" << std::endl;
     pcapSend->closePcap();
     //

    send(packet->dup(), gate("fedOut"));
}

/**
 * This method handles configuration messages.
 * If the number of radios is 0, no radio will be used
 */
void MosaicProxyApp::handleConfiguration(MosaicConfigurationCmd * cmd) {
    //channels are not alternatingly scheduled
    //For now we ignore georouting, so an interface is either there and fully configured or removed
    if (cmd->getNumRadios() == 0) {  //Disconnect radios from medium
        connectRadios(0);
        radio0Channel = -1;
        radio1Channel = -1;
        //It *should* not be necessary to change the IP address
        return;
    }
    if (ie0 == nullptr || ie1 == nullptr) {
        return; //somehow there are not the correct interfaces in the interface table.
    }
    if (cmd->getNumRadios() == 1) {
        //connect the wanted number of radios
        connectRadios(1);
        if (cmd->getNumchannels0() == 1) { //simple case
            //set channel and power
            radio0->setChannelNumber(cmd->getChannel00());
            EV << "Setting channel " << cmd->getChannel00() << " on " << radio0->getFullName() << " (" << radio0->getTransmitter()->getInfoStringRepresentation() << ")" << std::endl;
            if (cmd->getPower0() > -1) {
                inet::W power = inet::W(cmd->getPower0());//We get the power in mW
                radio0->setPower(power/1000); //thus we have to divide by 1000 to get W
            }
            radio0Channel = cmd->getChannel00();
        } else if (cmd->getNumchannels0() == 2) { //switching case
            //Not yet implemented
        }

        //now configure the IP address
        ie0->getProtocolData<inet::Ipv4InterfaceData>()->setIPAddress(cmd->getIp0());
        ie0->getProtocolData<inet::Ipv4InterfaceData>()->setNetmask(cmd->getSubnet0());
        ie0->setBroadcast(true);
        return;
    }
    if (cmd->getNumRadios() == 2) {
        //connect the wanted number of radios
        connectRadios(2);
        if (cmd->getNumchannels0() == 1 && cmd->getNumchannels1() == 1) {
            //configure the first radio
            EV << "Setting channel " << cmd->getChannel00() << " on " << radio0->getFullName() << " (" << radio0->getTransmitter()->getInfoStringRepresentation() << ")" << std::endl;
            radio0->setChannelNumber(cmd->getChannel00());
            if (cmd->getPower0() > -1) {
                inet::mW power0 = inet::W(cmd->getPower0());//We get the power in mW
                radio0->setPower(power0/1000); //thus we have to divide by 1000 to get W
            }
            radio0Channel = cmd->getChannel00();
            //configure the second radio
            EV << "Setting channel " << cmd->getChannel10() << " on "  << radio1->getFullName() << " (" << radio0->getTransmitter()->getInfoStringRepresentation() << ")" << std::endl;
            radio1->setChannelNumber(cmd->getChannel10());
            if (cmd->getPower1() > -1) {
                inet::W power1 = inet::W(cmd->getPower1());//We get the power in mW
                radio1->setPower(power1/1000); //thus we have to divide by 1000 to get W
            }
            radio1Channel = cmd->getChannel10();
        } else {
            return; //we do not support dual radio dual channel yet
        }

        //configure the IP addresses of the two radios
        ie0->getProtocolData<inet::Ipv4InterfaceData>()->setIPAddress(cmd->getIp0());
        ie0->getProtocolData<inet::Ipv4InterfaceData>()->setNetmask(cmd->getSubnet0());
        ie0->setBroadcast(true);
        ie1->getProtocolData<inet::Ipv4InterfaceData>()->setIPAddress(cmd->getIp1());
        ie1->getProtocolData<inet::Ipv4InterfaceData>()->setNetmask(cmd->getSubnet1());
        ie1->setBroadcast(true);
        return;
    }
}

/**
 * Sets the mode of the radios
 * 0 - no radio will be turned on
 * 1 - the first (wlan0) interfaces radio will be turned on
 * 2 - the first (wlan0) and the second (wlan1) radio will be turned on
 * @param number the number of radios
 */
void MosaicProxyApp::connectRadios(int number) {
    switch(number) {
    case 0:
        if (numRadios > 0) {
            radio0->setRadioMode(inet::physicallayer::IRadio::RADIO_MODE_OFF);
            if (numRadios > 1) {
                radio1->setRadioMode(inet::physicallayer::IRadio::RADIO_MODE_OFF);
            }
        }
        numRadios = 0;
        return;
    case 1:
        if (numRadios == 0) {
            radio0->setRadioMode(inet::physicallayer::IRadio::RADIO_MODE_RECEIVER);
        }
        if (numRadios == 2) {
            radio1->setRadioMode(inet::physicallayer::IRadio::RADIO_MODE_OFF);
        }
        numRadios = 1;
        return;
    case 2:
        if (numRadios < 2) {
            if (numRadios == 0) {
                radio0->setRadioMode(inet::physicallayer::IRadio::RADIO_MODE_RECEIVER);
            }
            radio1->setRadioMode(inet::physicallayer::IRadio::RADIO_MODE_RECEIVER);
        }
        numRadios = 2;
        return;
    default: return;
    }
}

void MosaicProxyApp::handleMessageWhenUp(omnetpp::cMessage * msg) {
    if (msg->arrivedOn("fedIn")) {
        // from federate
        MosaicConfigurationCmd * cmd;
        if ((cmd = dynamic_cast<MosaicConfigurationCmd *>(msg))) {
            handleConfiguration(cmd);
        } else if (numRadios > 0){    //do nothing if there are no radios
            sendPacket(msg);
        }
    } else if (msg->arrivedOn("socketIn")) {
        // from radio
        receivePacket(msg);
    }
    delete msg;
}

} // namespace omnetpp_federate

