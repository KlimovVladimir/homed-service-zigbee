#ifndef ZNSP_H
#define ZNSP_H

#define ZNPS_REQUEST_TIMEOUT                        10000

#define SLIP_END                                    0xC0
#define SLIP_ESC                                    0xDB
#define SLIP_ESC_END                                0xDC
#define SLIP_ESC_ESC                                0xDD

//Control Type
#define REQUEST                                     0x0000
#define RESPONSE                                    0x0010
#define INDICATION                                  0x0020

//Network command ids
#define ZNSP_NETWORK_INIT                           0x0000
#define ZNSP_NETWORK_START                          0x0001
#define ZNSP_NETWORK_STATE                          0x0002
#define ZNSP_NETWORK_STACK_STATUS_HANDLER           0x0003
#define ZNSP_NETWORK_FORM                           0x0004
#define ZNSP_NETWORK_PERMIT_JOINING                 0x0005
#define ZNSP_NETWORK_JOIN                           0x0006
#define ZNSP_NETWORK_LEAVE                          0x0007
#define ZNSP_NETWORK_START_SCAN                     0x0008
#define ZNSP_NETWORK_SCAN_COMPLETE_HANDLER          0x0009
#define ZNSP_NETWORK_STOP_SCAN                      0x000A
#define ZNSP_NETWORK_PAN_ID_GET                     0x000B
#define ZNSP_NETWORK_PAN_ID_SET                     0x000C
#define ZNSP_NETWORK_EXTENDED_PAN_ID_GET            0x000D
#define ZNSP_NETWORK_EXTENDED_PAN_ID_SET            0x000E
#define ZNSP_NETWORK_PRIMARY_CHANNEL_GET            0x000F
#define ZNSP_NETWORK_PRIMARY_CHANNEL_SET            0x0010
#define ZNSP_NETWORK_SECONDARY_CHANNEL_GET          0x0011
#define ZNSP_NETWORK_SECONDARY_CHANNEL_SET          0x0012
#define ZNSP_NETWORK_CHANNEL_GET                    0x0013
#define ZNSP_NETWORK_CHANNEL_SET                    0x0014
#define ZNSP_NETWORK_TXPOWER_GET                    0x0015
#define ZNSP_NETWORK_TXPOWER_SET                    0x0016
#define ZNSP_NETWORK_PRIMARY_KEY_GET                0x0017
#define ZNSP_NETWORK_PRIMARY_KEY_SET                0x0018
#define ZNSP_NETWORK_FRAME_COUNT_GET                0x0019
#define ZNSP_NETWORK_FRAME_COUNT_SET                0x001A
#define ZNSP_NETWORK_ROLE_GET                       0x001B
#define ZNSP_NETWORK_ROLE_SET                       0x001C
#define ZNSP_NETWORK_SHORT_ADDRESS_GET              0x001D
#define ZNSP_NETWORK_SHORT_ADDRESS_SET              0x001E
#define ZNSP_NETWORK_LONG_ADDRESS_GET               0x001F
#define ZNSP_NETWORK_LONG_ADDRESS_SET               0x0020
#define ZNSP_NETWORK_CHANNEL_MASKS_GET              0x0021
#define ZNSP_NETWORK_CHANNEL_MASKS_SET              0x0022
#define ZNSP_NETWORK_UPDATE_ID_GET                  0x0023
#define ZNSP_NETWORK_UPDATE_ID_SET                  0x0024
#define ZNSP_NETWORK_TRUST_CENTER_ADDR_GET          0x0025
#define ZNSP_NETWORK_TRUST_CENTER_ADDR_SET          0x0026
#define ZNSP_NETWORK_LINK_KEY_GET                   0x0027
#define ZNSP_NETWORK_LINK_KEY_SET                   0x0028
#define ZNSP_NETWORK_SECURE_MODE_GET                0x0029
#define ZNSP_NETWORK_SECURE_MODE_SET                0x002A
#define ZNSP_NETWORK_PREDEFINED_PANID               0x002B
#define ZNSP_NETWORK_SHORT_TO_IEEE                  0x002C
#define ZNSP_NETWORK_IEEE_TO_SHORT                  0x002D

//ZCL command ids
#define ZNSP_ZCL_ENDPOINT_ADD                       0x0100
#define ZNSP_ZCL_ENDPOINT_DEL                       0x0101
#define ZNSP_ZCL_ATTR_READ                          0x0102
#define ZNSP_ZCL_ATTR_WRITE                         0x0103
#define ZNSP_ZCL_ATTR_REPORT                        0x0104
#define ZNSP_ZCL_ATTR_DISC                          0x0105
#define ZNSP_ZCL_READ                               0x0106
#define ZNSP_ZCL_WRITE                              0x0107
#define ZNSP_ZCL_REPORT_CONFIG                      0x0108

//ZDO command ids
#define ZNSP_ZDO_BIND_SET                           0x0200
#define ZNSP_ZDO_UNBIND_SET                         0x0201
#define ZNSP_ZDO_FIND_MATCH                         0x0202

//APS command ids
#define ZNSP_APS_DATA_REQUEST                       0x0300
#define ZNSP_APS_DATA_INDICATION                    0x0301
#define ZNSP_APS_DATA_CONFIRM                       0x0302

#define ZNSP_SYSTEM_RESET                           0x0400
#define ZNSP_SYSTEM_FACTORY                         0x0401
#define ZNSP_SYSTEM_FIRMWARE                        0x0402
#define ZNSP_SYSTEM_MODEL                           0x0403
#define ZNSP_SYSTEM_MANUFACTURER                    0x0404

#include "adapter.h"

#pragma pack(push, 1)

struct frameHeaderStruct
{
    quint16 flags;
    quint16 id;
    quint8  sequence;
    quint16 length;
};

struct apsDataRequestStruct
{
    quint64 ieeeAddress;
    quint8 dstEndpointId;
    quint8 srcEndpointId;
    quint8 dstMode;
    quint16 profileId;
    quint16 clusterId;
    quint8 txMode;
    quint8 alias;
    quint16 srcAlias;
    quint8 aliasSeq;
    quint8 radius;
    quint32 asduLength;
};

struct apsDataIndicatonStruct
{
    quint8 states;
    quint8 dstAddressMode;
    quint64 dstIEEEAddress;
    quint8 dstEndpointId;
    quint8 srcAddressMode;
    quint64 srcIEEEAddress;
    quint8 srcEndpointId;
    quint16 profileId;
    quint16 clusterId;
    quint8 indicationStatus;
    quint8 securityStatus;
    quint8 lqi;
    quint32 rxTime;
    quint8 dataLength;
};

struct zdoBindSetStruct
{
    quint64 srcAddress;
    quint8 srcEndpointId;
    quint16 clusterId;
    quint8 dstMode;
    quint64 dstAddress;
    quint8 dstEndpointId;
    quint16 networkAddress;
    quint32 userCb;
    quint32 userCtx;
};

struct nwkFormationStruct
{
    quint8 role;
    quint8 maxChildren;
    quint8 policy;
    quint32 keepAlive;
};

#pragma pack(pop)

class ZNSP : public Adapter
{
    Q_OBJECT

public:

    ZNSP(QSettings *config, QObject *parent);

    bool unicastRequest(quint8 id, quint16 networkAddress, quint8 srcEndPointId, quint8 dstEndPointId, quint16 clusterId, const QByteArray &payload) override;
    bool multicastRequest(quint8 id, quint16 groupId, quint8 srcEndPointId, quint8 dstEndPointId, quint16 clusterId, const QByteArray &payload) override;

    bool unicastInterPanRequest(quint8 id, const QByteArray &ieeeAddress, quint16 clusterId, const QByteArray &payload) override;
    bool broadcastInterPanRequest(quint8 id, quint16 clusterId, const QByteArray &payload) override;

    bool setInterPanChannel(quint8 channel) override;
    void resetInterPanChannel(void) override;

    bool zdoRequest(quint8 id, quint16 networkAddress, quint16 clusterId, const QByteArray &data = QByteArray()) override;
    bool bindRequest(quint8 id, quint16 networkAddress, quint8 endpointId, quint16 clusterId, const QByteArray &address, quint8 dstEndpointId, bool unbind = false) override;
    bool leaveRequest(quint8 id, quint16 networkAddress) override;
    bool lqiRequest(quint8 id, quint16 networkAddress, quint8 index) override;

private:

    quint16 m_command;
    QByteArray m_replyData;
    bool m_commandReply;

    QByteArray m_networkKey;
    //QList <setTCPolicyStruct> m_policy;

    quint8 m_packet_seq;

    quint16 getCRC16(quint8 *data, quint32 length);
    QByteArray slip_encode(QByteArray &data);
    QByteArray slip_decode(QByteArray &data);
    inline quint8 getSeq() {m_packet_seq = (m_packet_seq + 1) % 255; return m_packet_seq;}

    bool sendRequest(quint16 command, const QByteArray &data = QByteArray(), bool notify = false);
    void sendAck();
    void parsePacket(quint16 flags, quint16 command, const QByteArray &data);

    bool startCoordinator(void);

    void softReset(void) override;
    void parseData(QByteArray &buffer) override;
    bool permitJoin(bool enabled) override;

private slots:

    void handleQueue(void) override;

signals:

    void dataReceived(void);
    void notifyReceived(void);

};

#endif
