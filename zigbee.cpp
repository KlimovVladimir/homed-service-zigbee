#include <QtEndian>
#include <QFile>
#include <QRandomGenerator>
#include "ezsp.h"
#include "gpio.h"
#include "logger.h"
#include "zcl.h"
#include "zigbee.h"
#include "zstack.h"

ZigBee::ZigBee(QSettings *config, QObject *parent) : QObject(parent), m_config(config), m_neighborsTimer(new QTimer(this)), m_queuesTimer(new QTimer(this)), m_statusLedTimer(new QTimer(this)), m_devices(new DeviceList(m_config)), m_transactionId(0)
{
    ActionObject::registerMetaTypes();
    PollObject::registerMetaTypes();
    PropertyObject::registerMetaTypes();
    ReportingObject::registerMetaTypes();

    m_statusLedPin = m_config->value("gpio/status", "-1").toString();
    m_blinkLedPin = m_config->value("gpio/blink", "-1").toString();
    m_libraryFile = m_config->value("zigbee/library", "/usr/share/homed/zigbee.json").toString(); // TODO: make it QFile?

    connect(m_neighborsTimer, &QTimer::timeout, this, &ZigBee::updateNeighbors);
    connect(m_queuesTimer, &QTimer::timeout, this, &ZigBee::handleQueue);
    connect(m_statusLedTimer, &QTimer::timeout, this, &ZigBee::updateStatusLed);
    connect(m_devices, &DeviceList::statusStored, this, &ZigBee::statusStored);

    GPIO::direction(m_statusLedPin, GPIO::Output);
    GPIO::setStatus(m_statusLedPin, m_statusLedPin != m_blinkLedPin);

    if (m_statusLedPin == m_blinkLedPin)
        return;

    GPIO::direction(m_blinkLedPin, GPIO::Output);
    GPIO::setStatus(m_blinkLedPin, false);
}

void ZigBee::init(void)
{
    QList <QString> list = {"ezsp", "znp"};
    QString adapterType = m_config->value("zigbee/adapter", "znp").toString();

    for (auto it = m_devices->begin(); it != m_devices->end(); it++)
        if (it.value()->interviewFinished())
            setupDevice(it.value());

    switch (list.indexOf(adapterType))
    {
        case 0:  m_adapter = new EZSP(m_config, this); break;
        case 1:  m_adapter = new ZStack(m_config, this); break;
        default: logWarning << "Unrecognized adapter type" << adapterType; return;
    }

    connect(m_adapter, &Adapter::coordinatorReady, this, &ZigBee::coordinatorReady);
    connect(m_adapter, &Adapter::permitJoinUpdated, this, &ZigBee::permitJoinUpdated);

    m_adapter->init();
}

void ZigBee::setPermitJoin(bool enabled)
{
    m_devices->setPermitJoin(enabled);
    m_adapter->setPermitJoin(enabled);
    m_devices->storeStatus();
}

void ZigBee::setDeviceName(const QByteArray &ieeeAddress, const QString &name)
{
    auto it = m_devices->find(ieeeAddress);

    if (it == m_devices->end())
        return;

    it.value()->setName(name);
}

void ZigBee::removeDevice(const QByteArray &ieeeAddress)
{
    auto it = m_devices->find(ieeeAddress);

    if (it == m_devices->end())
        return;

    logInfo << "Device" << it.value()->name() << "removed";

    m_devices->erase(it);
    m_devices->storeStatus();
}

void ZigBee::updateDevice(const QByteArray &ieeeAddress, bool reportings)
{
    Device device = m_devices->value(ieeeAddress);

    if (device.isNull())
        return;

    setupDevice(device);

    if (!reportings)
    {
        logInfo << "Device" << device->name() << "configuration updated without reportings";
        return;
    }

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
        for (int i = 0; i < it.value()->reportings().count(); i++)
            configureReporting(it.value(), it.value()->reportings().at(i));

    logInfo << "Device" << device->name() << "configuration updated";
}

void ZigBee::updateReporting(const QByteArray &ieeeAddress, quint8 endpointId, const QString &reportingName, quint16 minInterval, quint16 maxInterval, quint16 valueChange)
{
    Device device = m_devices->value(ieeeAddress);

    if (device.isNull())
        return;

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
    {
        if (endpointId && it.value()->id() != endpointId)
            continue;

        for (int i = 0; i < it.value()->reportings().count(); i++)
        {
            const Reporting &reporting = it.value()->reportings().at(i);

            if (!reportingName.isEmpty() && reporting->name() != reportingName)
                continue;

            if (minInterval)
                reporting->setMinInterval(minInterval);

            if (maxInterval)
                reporting->setMaxInterval(maxInterval);

            if (valueChange)
                reporting->setValueChange(valueChange);

            configureReporting(it.value(), reporting);
        }
    }
}

void ZigBee::bindingControl(const QByteArray &ieeeAddress, quint8 endpointId, quint16 clusterId, const QVariant &dstAddress, quint8 dstEndpointId, bool unbind)
{
    auto it = m_devices->find(ieeeAddress);

    if (it == m_devices->end())
        return;

    switch (dstAddress.type())
    {
        case QVariant::LongLong:
        {
            quint16 value = qToLittleEndian <quint16> (dstAddress.toInt());
            enqueueBindRequest(it.value(), endpointId, clusterId, QByteArray(reinterpret_cast <char*> (&value), sizeof(value)), 0xFF, unbind);
            break;
        }

        case QVariant::String:
        {
            enqueueBindRequest(it.value(), endpointId, clusterId, QByteArray::fromHex(dstAddress.toString().toUtf8()), dstEndpointId, unbind);
            break;
        }

        default:
            break;
    }
}

void ZigBee::groupControl(const QByteArray &ieeeAddress, quint8 endpointId, quint16 groupId, bool remove)
{
    auto it = m_devices->find(ieeeAddress);
    zclHeaderStruct header;

    if (it == m_devices->end())
        return;

    header.frameControl = FC_CLUSTER_SPECIFIC;
    header.transactionId = m_transactionId++;
    header.commandId = remove ? 0x03 : 0x00;

    groupId = qFromLittleEndian(groupId);
    enqueueDataRequest(it.value(), endpointId ? endpointId : 1, CLUSTER_GROUPS, QByteArray(reinterpret_cast <char*> (&header), sizeof(header)).append(reinterpret_cast <char*> (&groupId), sizeof(groupId)).append(remove ? 0 : 1, 0x00));
}

void ZigBee::removeAllGroups(const QByteArray &ieeeAddress, quint8 endpointId)
{
    auto it = m_devices->find(ieeeAddress);
    zclHeaderStruct header;

    if (it == m_devices->end())
        return;

    header.frameControl = FC_CLUSTER_SPECIFIC;
    header.transactionId = m_transactionId++;
    header.commandId = 0x04;

    enqueueDataRequest(it.value(), endpointId ? endpointId : 1, CLUSTER_GROUPS, QByteArray(reinterpret_cast <char*> (&header), sizeof(header)), QString("remove all groups request"));
}

void ZigBee::otaUpgrade(const QByteArray &ieeeAddress, quint8 endpointId, const QString &fileName)
{
    auto it = m_devices->find(ieeeAddress);
    zclHeaderStruct header;
    otaImageNotifyStruct payload;

    if (it == m_devices->end() || fileName.isEmpty() || !QFile::exists(fileName))
        return;

    m_otaUpgradeFile = fileName;

    header.frameControl = FC_CLUSTER_SPECIFIC | FC_SERVER_TO_CLIENT;
    header.transactionId = m_transactionId++;
    header.commandId = 0x00;

    payload.type = 0x00;
    payload.jitter = 0x64; // TODO: check this

    enqueueDataRequest(it.value(), endpointId ? endpointId : 1, CLUSTER_OTA_UPGRADE, QByteArray(reinterpret_cast <char*> (&header), sizeof(header)).append(reinterpret_cast <char*> (&payload), sizeof(payload)));
}

void ZigBee::touchLinkRequest(const QByteArray &ieeeAddress, quint8 channel, bool reset)
{
    if (m_adapter->setInterPanEndpointId(0x0C))
    {
        m_queuesTimer->stop();

        if (reset)
            touchLinkReset(ieeeAddress, channel);
        else
            touchLinkScan();

        m_adapter->resetInterPan();
        m_queuesTimer->start();
    }
}

void ZigBee::deviceAction(const QByteArray &ieeeAddress, quint8 endpointId, const QString &actionName, const QVariant &actionData)
{
    Device device = m_devices->value(ieeeAddress);

    if (device.isNull())
        return;

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
    {
        if (endpointId && it.value()->id() != endpointId)
            continue;

        for (int i = 0; i < it.value()->actions().count(); i++)
        {
            const Action &action = it.value()->actions().at(i);

            if (action->name() == actionName)
            {
                QByteArray data = action->request(actionData);

                if (data.isEmpty())
                    continue;

                enqueueDataRequest(device, it.value()->id(), action->clusterId(), data, QString("%1 action").arg(action->name()));
                break;
            }
        }
    }
}

void ZigBee::groupAction(quint16 groupId, const QString &actionName, const QVariant &actionData)
{
    int type = QMetaType::type(QString(actionName).append("Action").toUtf8());

    if (type)
    {
        Action action(reinterpret_cast <ActionObject*> (QMetaType::create(type)));
        QByteArray data = action->request(actionData);

        if (data.isEmpty())
            return;

        m_adapter->extendedDataRequest(groupId, 0xFF, 0x0000, 0x01, action->clusterId(), data, true);
    }
}

Endpoint ZigBee::getEndpoint(const Device &device, quint8 endpointId)
{
    auto it = device->endpoints().find(endpointId);

    if (it == device->endpoints().end())
        it = device->endpoints().insert(endpointId, Endpoint(new EndpointObject(endpointId, device)));

    return it.value();
}

void ZigBee::enqueueBindRequest(const Device &device, quint8 endpointId, quint16 clusterId, const QByteArray &dstAddress, quint8 dstEndpointId, bool unbind)
{
    BindRequest request(new BindRequestObject(device, endpointId, clusterId, dstAddress, dstEndpointId, unbind));

    for (int i = 0; i < m_bindQueue.length(); i++)
        if (*m_bindQueue.at(i).data() == *request.data())
            return;

    m_bindQueue.enqueue(request);
}

void ZigBee::enqueueDataRequest(const Device &device, quint8 endpointId, quint16 clusterId, const QByteArray &data, const QString &name)
{
    DataRequest request(new DataRequestObject(device, endpointId, clusterId, data, name));

    for (int i = 0; i < m_dataQueue.length(); i++)
        if (*m_dataQueue.at(i).data() == *request.data())
            return;

    m_dataQueue.enqueue(request);
}

void ZigBee::setupDevice(const Device &device)
{
    QFile file(m_libraryFile);
    QJsonArray array;
    bool check = false;

    if (!file.open(QFile::ReadOnly | QFile::Text))
    {
        logWarning << "Can't open library file, devices not loaded";
        return;
    }

    array = QJsonDocument::fromJson(file.readAll()).object().value(device->manufacturerName()).toArray();
    file.close();

    if (array.isEmpty())
    {
        logWarning << "Device" << device->name() << "manufacturer name" << device->manufacturerName() << "unrecognized";
        return;
    }

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
    {
        disconnect(it.value()->timer(), &QTimer::timeout, this, &ZigBee::pollAttributes);
        it.value()->timer()->stop();

        it.value()->actions().clear();
        it.value()->properties().clear();
        it.value()->reportings().clear();
        it.value()->polls().clear();
    }

    for (auto it = array.begin(); it != array.end(); it++)
    {
        QJsonObject json = it->toObject();
        QJsonArray array = json.value("modelNames").toArray();

        if (array.contains(device->modelName()))
        {
            QJsonValue endpoinId = json.value("endpointId");
            QList <QVariant> list = endpoinId.type() == QJsonValue::Array ? endpoinId.toArray().toVariantList() : QList <QVariant> {endpoinId.toInt(1)};

            for (int i = 0; i < list.count(); i++)
                setupEndpoint(getEndpoint(device, static_cast <quint8> (list.at(i).toInt())), json);

            if (device->description().isEmpty())
                device->setDescription(json.value("description").toString());

            device->setMultipleEndpoints(endpoinId.type() == QJsonValue::Array);
            check = true;
        }
    }

    if (check)
        return;

    logWarning << "Device" << device->name() << "model name" << device->modelName() << "unrecognized";
}

void ZigBee::setupEndpoint(const Endpoint &endpoint, const QJsonObject &json)
{
    Device device = endpoint->device();
    QJsonArray actions = json.value("actions").toArray(), properties = json.value("properties").toArray(), reportings = json.value("reportings").toArray(), polls = json.value("polls").toArray();
    quint32 pollInterval = static_cast <quint32> (json.value("pollInterval").toInt());

    for (auto it = actions.begin(); it != actions.end(); it++)
    {
        int type = QMetaType::type(QString(it->toString()).append("Action").toUtf8());

        if (type)
        {
            Action action(reinterpret_cast <ActionObject*> (QMetaType::create(type)));
            endpoint->actions().append(action);
            continue;
        }

        logWarning << "Device" << device->name() << "endpoint" << QString::asprintf("0x%02X", endpoint->id()) << "action" << it->toString() << "unrecognized";
    }

    for (auto it = properties.begin(); it != properties.end(); it++)
    {
        int type = QMetaType::type(QString(it->toString()).append("Property").toUtf8());

        if (type)
        {
            Property property(reinterpret_cast <PropertyObject*> (QMetaType::create(type)));
            property->setVersion(device->version());
            property->setModel(device->modelName());
            endpoint->properties().append(property);
            continue;
        }

        logWarning << "Device" << device->name() << "endpoint" << QString::asprintf("0x%02X", endpoint->id()) << "property" << it->toString() << "unrecognized";
    }

    for (auto it = reportings.begin(); it != reportings.end(); it++)
    {
        int type = QMetaType::type(QString(it->toString()).append("Reporting").toUtf8());

        if (type)
        {
            Reporting reporting(reinterpret_cast <ReportingObject*> (QMetaType::create(type)));
            endpoint->reportings().append(reporting);
            continue;
        }

        logWarning << "Device" << device->name() << "endpoint" << QString::asprintf("0x%02X", endpoint->id()) << "reporting" << it->toString() << "unrecognized";
    }

    for (auto it = polls.begin(); it != polls.end(); it++)
    {
        int type = QMetaType::type(QString(it->toString()).append("Poll").toUtf8());

        if (type)
        {
            Poll poll(reinterpret_cast <PollObject*> (QMetaType::create(type)));
            endpoint->polls().append(poll);
            continue;
        }

        logWarning << "Device" << device->name() << "endpoint" << QString::asprintf("0x%02X", endpoint->id()) << "poll" << it->toString() << "unrecognized";
    }

    if (!endpoint->polls().isEmpty())
    {
        for (int i = 0; i < endpoint->polls().count(); i++)
        {
            const Poll &poll = endpoint->polls().at(i);
            readAttributes(device, endpoint->id(), poll->clusterId(), poll->attributes());
        }

        if (pollInterval)
        {
            connect(endpoint->timer(), &QTimer::timeout, this, &ZigBee::pollAttributes);
            endpoint->timer()->start(pollInterval * 1000);
        }
    }
}

void ZigBee::interviewDevice(const Device &device)
{
    if (device->interviewFinished())
        return;

    device->timer()->start(DEVICE_INTERVIEW_TIMEOUT);
    m_interviewQueue.enqueue(device);
}

void ZigBee::interviewRequest(const Device &device)
{
    if (device->manufacturerName().isEmpty() || device->modelName().isEmpty() || device->powerSource() == POWER_SOURCE_UNKNOWN)
    {
        if (!device->nodeDescriptorReceived())
        {
            if (!m_adapter->nodeDescriptorRequest(device->networkAddress()))
                interviewError(device, "node descriptor request failed");

            return;
        }

        if (!device->activeEndpointsReceived())
        {
            if (!m_adapter->activeEndpointsRequest(device->networkAddress()))
                interviewError(device, "active endpoints request failed");

            return;
        }

        for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
        {
            if (it.value()->profileId() || it.value()->deviceId())
                continue;

            if (!m_adapter->simpleDescriptorRequest(device->networkAddress(), it.key()))
                interviewError(device, QString::asprintf("endpoint 0x%02X simple descriptor request failed", it.key()));

            return;
        }

        for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
        {
            if (!it.value()->inClusters().contains(CLUSTER_BASIC))
                continue;

            if (!readAttributes(device, it.key(), CLUSTER_BASIC, {0x0001, 0x0004, 0x0005, 0x0007}, false))
                interviewError(device, "read basic attributes request failed");

            return;
        }

        interviewError(device, "device has empty manufacturer name or model name");
    }

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
    {
        if (!it.value()->inClusters().contains(CLUSTER_IAS_ZONE))
            continue;

        switch (it.value()->zoneStatus())
        {
            case ZoneStatus::Unknown:
            {
                if (!readAttributes(device, it.key(), CLUSTER_IAS_ZONE, {0x0000, 0x0010}, false))
                    interviewError(device, "read current IAS zone status request failed");

                return;
            }

            case ZoneStatus::SetAddress:
            {
                zclHeaderStruct header;
                writeArrtibutesStruct payload;
                quint64 ieeeAddress = m_adapter->ieeeAddress();

                header.frameControl = FC_DISABLE_DEFAULT_RESPONSE;
                header.transactionId = m_transactionId++;
                header.commandId = CMD_WRITE_ATTRIBUTES;

                payload.attributeId = qToLittleEndian <quint16> (0x0010);
                payload.dataType = DATA_TYPE_IEEE_ADDRESS;

                if (!m_adapter->dataRequest(device->networkAddress(), it.value()->id(), CLUSTER_IAS_ZONE, QByteArray(reinterpret_cast <char*> (&header), sizeof(header)).append(reinterpret_cast <char*> (&payload), sizeof(payload)).append(reinterpret_cast <char*> (&ieeeAddress), sizeof(ieeeAddress))))
                    interviewError(device, "write IAS zone CIE address request failed");

                return;
            }

            case ZoneStatus::Enroll:
            {
                zclHeaderStruct header;
                iasZoneEnrollResponseStruct payload;

                header.frameControl =  FC_CLUSTER_SPECIFIC | FC_DISABLE_DEFAULT_RESPONSE;
                header.transactionId = m_transactionId++;
                header.commandId = 0x00;

                payload.responseCode = 0x00;
                payload.zoneId = 0x42;

                if (!m_adapter->dataRequest(device->networkAddress(), it.value()->id(), CLUSTER_IAS_ZONE, QByteArray(reinterpret_cast <char*> (&header), sizeof(header)).append(reinterpret_cast <char*> (&payload), sizeof(payload))))
                    interviewError(device, "enroll IAS zone request failed");
                else if (!readAttributes(device, it.key(), CLUSTER_IAS_ZONE, {0x0000, 0x0010}, false))
                    interviewError(device, "read updated IAS zone status request failed");

                return;
            }

            case ZoneStatus::Enrolled:
                logInfo << "Device" << device->name() << "endpoint" << QString::asprintf("0x%02X", it.value()->id()) << "IAS zone enrolled";
                break;
        }
    }

    interviewFinished(device);
}

void ZigBee::interviewFinished(const Device &device)
{
    setupDevice(device);

    if (device->description().isEmpty())
        logInfo << "Device" << device->name() << "manufacturer name is" << device->manufacturerName() << "and model name is" << device->modelName();
    else
        logInfo << "Device" << device->name() << "is" << device->description();

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
        for (int i = 0; i < it.value()->reportings().count(); i++)
            configureReporting(it.value(), it.value()->reportings().at(i));

    logInfo << "Device" << device->name() << "interview finished";

    device->timer()->stop();
    device->setInterviewFinished();

    m_devices->storeStatus();
}

void ZigBee::interviewError(const Device &device, const QString &reason)
{
    if (!device->timer()->isActive())
        return;

    logWarning << "Device" << device->name() << "interview aborted:" << reason;
    device->timer()->stop();
}

void ZigBee::configureReporting(const Endpoint &endpoint, const Reporting &reporting)
{
    Device device = endpoint->device();
    zclHeaderStruct header;
    QByteArray payload;

    header.frameControl = 0x00;
    header.transactionId = m_transactionId++;
    header.commandId = CMD_CONFIGURE_REPORTING;

    for (int i = 0; i < reporting->attributes().count(); i++)
    {
        configureReportingStruct item;

        item.direction = 0x00;
        item.attributeId = qToLittleEndian(reporting->attributes().at(i));
        item.dataType = reporting->dataType();
        item.minInterval = qToLittleEndian(reporting->minInterval());
        item.maxInterval = qToLittleEndian(reporting->maxInterval());
        item.valueChange = qToLittleEndian(reporting->valueChange());

        payload.append(reinterpret_cast <char*> (&item), sizeof(item) - sizeof(item.valueChange) + zclDataSize(item.dataType));
    }

    enqueueBindRequest(device, endpoint->id(), reporting->clusterId());
    enqueueDataRequest(device, endpoint->id(), reporting->clusterId(), QByteArray(reinterpret_cast <char*> (&header), sizeof(header)).append(payload), QString("%1 reporting configuration").arg(reporting->name()));
}

bool ZigBee::readAttributes(const Device &device, quint8 endpointId, quint16 clusterId, QList <quint16> attributes, bool enqueue)
{
    zclHeaderStruct header;
    QByteArray payload;

    header.frameControl = 0x00;
    header.transactionId = m_transactionId++;
    header.commandId = CMD_READ_ATTRIBUTES;

    for (int i = 0; i < attributes.count(); i++)
    {
        quint16 attributeId = qToLittleEndian(attributes.at(i));
        payload.append(reinterpret_cast <char*> (&attributeId), sizeof(attributeId));
    }

    if (enqueue)
    {
        enqueueDataRequest(device, endpointId, clusterId, QByteArray(reinterpret_cast <char*> (&header), sizeof(header)).append(payload));
        return true;
    }

    return m_adapter->dataRequest(device->networkAddress(), endpointId, clusterId, QByteArray(reinterpret_cast <char*> (&header), sizeof(header)).append(payload));
}

void ZigBee::parseAttribute(const Endpoint &endpoint, quint16 clusterId, quint16 attributeId, quint8 dataType, const QByteArray &data)
{
    Device device = endpoint->device();
    bool check = false;

    if (clusterId == CLUSTER_BASIC) // TODO: check if any devices sends some data via basic cluster
    {
        switch (attributeId)
        {
            case 0x0001:

                if (dataType != DATA_TYPE_8BIT_UNSIGNED)
                    return;

                device->setVersion(static_cast <quint8> (data.at(0)));
                break;

            case 0x0004:

                if (dataType != DATA_TYPE_CHARACTER_STRING)
                    return;

                device->setManufacturerName(QString(data).trimmed());
                break;

            case 0x0005:

                if (dataType != DATA_TYPE_CHARACTER_STRING)
                    return;

                device->setModelName(QString(data).trimmed());

                if (device->manufacturerName().isEmpty() && device->modelName().startsWith("lumi.sensor")) // some LUMI devices send modelName attribute on join
                {
                    device->setPowerSource(POWER_SOURCE_BATTERY);
                    device->setManufacturerName("LUMI");
                    interviewFinished(device);
                    return;
                }

                break;

            case 0x0007:

                if (dataType != DATA_TYPE_8BIT_ENUM)
                    return;

                device->setPowerSource(static_cast <quint8> (data.at(0)));
                break;
        }

        if (!device->interviewFinished() && !device->manufacturerName().isEmpty() && !device->modelName().isEmpty() && device->powerSource() != POWER_SOURCE_UNKNOWN)
        {
            QList <QString> tuya = // TUYA devices model names
            {
                "TS0001", "TS0002", "TS0004", "TS0004",
                "TS0011", "TS0012", "TS0013", "TS0014",
                "TS0201", "TS0202", "TS0203", "TS0204", "TS0205", "TS0207",
                "TS0601"
            };

            if (!device->manufacturerName().isEmpty() && tuya.contains(device->modelName()))
            {
                QList <QString> list = {"TS0001", "TS0011", "TS0201", "TS0202", "TS0207", "TS0601"};

                if (list.contains(device->modelName()))
                    device->setModelName(device->manufacturerName());

                device->setManufacturerName("TUYA");
            }

            interviewDevice(device);
        }

        return;
    }

    if (clusterId == CLUSTER_IAS_ZONE && (attributeId == 0x0000 || attributeId == 0x0010))
    {
        switch (attributeId)
        {
            case 0x0000:
            {
                if (dataType != DATA_TYPE_8BIT_ENUM)
                    return;

                endpoint->setZoneStatus(data.at(0) ? ZoneStatus::Enrolled : ZoneStatus::Enroll);
                break;
            }

            case 0x0010:
            {
                quint64 ieeeAddress = m_adapter->ieeeAddress();

                if (dataType != DATA_TYPE_IEEE_ADDRESS)
                    return;

                if (memcmp(&ieeeAddress, data.constData(), sizeof(ieeeAddress)))
                    endpoint->setZoneStatus(ZoneStatus::SetAddress);

                interviewDevice(device);
                break;
            }
        }

        return;
    }

    if (!device->interviewFinished())
        return;

    for (int i = 0; i < endpoint->properties().count(); i++)
    {
        const Property &property = endpoint->properties().at(i);

        if (property->clusterId() == clusterId)
        {
            QVariant value = property->value();

            property->parseAttribte(attributeId, dataType, data);
            check = true;

            if (property->value() == value)
                continue;

            endpoint->setDataUpdated(true);
        }
    }

    if (!check)
        logWarning << "No property found for device" << device->name() << "endpoint" << QString::asprintf("0x%02X", endpoint->id()) << "cluster" << QString::asprintf("0x%04X", clusterId) << "attribute" << QString::asprintf("0x%04X", attributeId) << "with data type" << QString::asprintf("0x%02X", dataType) << "and data" << data.toHex(':');
}

void ZigBee::clusterCommandReceived(const Endpoint &endpoint, quint16 clusterId, quint8 transactionId, quint8 commandId, const QByteArray &payload)
{
    Device device = endpoint->device();
    bool check = false;

    if (!device->interviewFinished())
        return;

    if (clusterId == CLUSTER_GROUPS)
    {
        switch (commandId)
        {
            case 0x00:
            case 0x03:
            {
                const groupControlResponseStruct *response = reinterpret_cast <const groupControlResponseStruct*> (payload.constData());

                switch (response->status)
                {
                    case STATUS_SUCCESS:
                        logInfo << "Device" << device->name() << "endpoint" << QString::asprintf("0x%02X", endpoint->id()) << "group" << qFromLittleEndian(response->grpoupId) << "successfully" << (commandId ? "removed" : "added");
                        break;

                    case STATUS_INSUFFICIENT_SPACE:
                        logWarning << "Device" << device->name() << "endpoint" << QString::asprintf("0x%02X", endpoint->id()) << "group" << qFromLittleEndian(response->grpoupId) << "not added, no free space available";
                        break;

                    case STATUS_DUPLICATE_EXISTS:
                        logWarning << "Device" << device->name() << "endpoint" << QString::asprintf("0x%02X", endpoint->id()) << "group" << qFromLittleEndian(response->grpoupId) << "already exists";
                        break;

                    case STATUS_NOT_FOUND:
                        logWarning << "Device" << device->name() << "endpoint" << QString::asprintf("0x%02X", endpoint->id()) << "group" << qFromLittleEndian(response->grpoupId) << "not found";
                        break;

                    default:
                        logWarning << "Device" << device->name() << "endpoint" << QString::asprintf("0x%02X", endpoint->id()) << "group" << qFromLittleEndian(response->grpoupId) << (commandId ? "remove" : "add") << "command status" << QString::asprintf("0x%02X", response->status) << "unrecognized";
                        break;
                }

                break;
            }

            default:
                logWarning << "Unrecognized group control command" << QString::asprintf("0x%02X", commandId) << "received from device" << device->name() << "with payload:" << payload.toHex(':');
                break;
        }

        return;
    }

    if (clusterId == CLUSTER_OTA_UPGRADE)
    {
        QFile file(m_otaUpgradeFile);
        otaFileHeaderStruct fileHeader;
        zclHeaderStruct zclHeader;

        memset(&fileHeader, 0, sizeof(fileHeader));

        if (file.exists() && file.open(QFile::ReadOnly))
            memcpy(&fileHeader, file.read(sizeof(fileHeader)).constData(), sizeof(fileHeader));

        zclHeader.frameControl = FC_CLUSTER_SPECIFIC | FC_SERVER_TO_CLIENT | FC_DISABLE_DEFAULT_RESPONSE;
        zclHeader.transactionId = transactionId;

        switch (commandId)
        {
            case 0x01:
            {
                const otaNextImageRequestStruct *request = reinterpret_cast <const otaNextImageRequestStruct*> (payload.constData());
                otaNextImageResponseStruct response;

                zclHeader.commandId = 0x02;

                if (!file.isOpen() || request->manufacturerCode != fileHeader.manufacturerCode || request->imageType != fileHeader.imageType)
                {
                    enqueueDataRequest(device, endpoint->id(), CLUSTER_OTA_UPGRADE, QByteArray(reinterpret_cast <char*> (&zclHeader), sizeof(zclHeader)).append(STATUS_NO_IMAGE_AVAILABLE));
                    break;
                }

                if (request->fileVersion == fileHeader.fileVersion)
                {
                    logInfo << "Device" << device->name() << "OTA upgrade not started, version match:" << QString::asprintf("0x%08X", qFromLittleEndian(request->fileVersion)).toUtf8().constData();
                    enqueueDataRequest(device, endpoint->id(), CLUSTER_OTA_UPGRADE, QByteArray(reinterpret_cast <char*> (&zclHeader), sizeof(zclHeader)).append(STATUS_NO_IMAGE_AVAILABLE));
                    break;
                }

                logInfo << "Device" << device->name() << "OTA upgrade started...";

                response.status = 0x00;
                response.manufacturerCode = fileHeader.manufacturerCode;
                response.imageType = fileHeader.imageType;
                response.fileVersion = fileHeader.fileVersion;
                response.imageSize = fileHeader.imageSize;

                enqueueDataRequest(device, endpoint->id(), CLUSTER_OTA_UPGRADE, QByteArray(reinterpret_cast <char*> (&zclHeader), sizeof(zclHeader)).append(reinterpret_cast <char*> (&response), sizeof(response)));
                break;
            }

            case 0x03:
            {
                const otaImageBlockRequestStruct *request = reinterpret_cast <const otaImageBlockRequestStruct*> (payload.constData());
                otaImageBlockResponseStruct response;
                QByteArray data;

                zclHeader.commandId = 0x05;

                if (!file.isOpen() || request->manufacturerCode != fileHeader.manufacturerCode || request->imageType != fileHeader.imageType ||request->fileVersion != fileHeader.fileVersion)
                {
                    enqueueDataRequest(device, endpoint->id(), CLUSTER_OTA_UPGRADE, QByteArray(reinterpret_cast <char*> (&zclHeader), sizeof(zclHeader)).append(STATUS_NO_IMAGE_AVAILABLE));
                    break;
                }

                file.seek(qFromLittleEndian(request->fileOffset));
                data = file.read(request->dataSizeMax);

                // TODO: use percentage here
                logInfo << "Device" << device->name() << "OTA upgrade writing" << data.length() << "bytes with offset" << QString::asprintf("0x%04X", qFromLittleEndian(request->fileOffset));

                response.status = 0x00;
                response.manufacturerCode = request->manufacturerCode;
                response.imageType = request->imageType;
                response.fileVersion = request->fileVersion;
                response.fileOffset = request->fileOffset;
                response.dataSize = static_cast <quint8> (data.length());

                enqueueDataRequest(device, endpoint->id(), CLUSTER_OTA_UPGRADE, QByteArray(reinterpret_cast <char*> (&zclHeader), sizeof(zclHeader)).append(reinterpret_cast <char*> (&response), sizeof(response)).append(data));
                break;
            }
            case 0x06:
            {
                const otaUpgradeEndRequestStruct *request = reinterpret_cast <const otaUpgradeEndRequestStruct*> (payload.constData());
                otaUpgradeEndResponseStruct response;

                zclHeader.commandId = 0x07;
                m_otaUpgradeFile.clear();

                if (request->status)
                {
                    logWarning << "Device" << device->name() << "OTA upgrade failed, status code:" << QString::asprintf("%02X", request->status);;
                    break;
                }

                logInfo << "Device" << device->name() << "OTA upgrade finished successfully";

                response.manufacturerCode = request->manufacturerCode;
                response.imageType = request->imageType;
                response.fileVersion = request->fileVersion;
                response.currentTime = 0;
                response.upgradeTime = 0;

                enqueueDataRequest(device, endpoint->id(), CLUSTER_OTA_UPGRADE, QByteArray(reinterpret_cast <char*> (&zclHeader), sizeof(zclHeader)).append(reinterpret_cast <char*> (&response), sizeof(response)));
                break;
            }

            default:
                logWarning << "Unrecognized OTA upgrade command" << QString::asprintf("0x%02X", commandId) << "received from device" << device->name() << "with payload:" << payload.toHex(':');
                break;
        }

        if (file.isOpen())
            file.close();

        return;
    }

    for (int i = 0; i < endpoint->properties().count(); i++)
    {
        const Property &property = endpoint->properties().at(i);

        if (property->clusterId() == clusterId)
        {
            QVariant value = property->value();

            property->parseCommand(commandId, payload);
            check = true;

            if (property->value() == value)
                continue;

            endpoint->setDataUpdated(true);
        }
    }

    if (!check)
        logWarning << "No property found for device" << device->name() << "endpoint" << QString::asprintf("0x%02X", endpoint->id()) << "cluster" << QString::asprintf("0x%04X", clusterId) << "command" << QString::asprintf("0x%02X", commandId) << "with payload" << payload.toHex(':');
}

void ZigBee::globalCommandReceived(const Endpoint &endpoint, quint16 clusterId, quint8 commandId, QByteArray payload)
{
    Device device = endpoint->device();

    switch (commandId)
    {
        case CMD_READ_ATTRIBUTES: // TODO: tyua sensor reading time cluster
        case CMD_CONFIGURE_REPORTING_RESPONSE:
        case CMD_DEFAULT_RESPONSE:
            break;

        case CMD_READ_ATTRIBUTES_RESPONSE:
        case CMD_REPORT_ATTRIBUTES:
        {
            while (payload.length() > 2)
            {
                quint8 dataType, offset, size = 0;
                quint16 attributeId;

                if (commandId == CMD_READ_ATTRIBUTES_RESPONSE)
                {
                    if (payload.at(2))
                        break;

                    dataType = static_cast <quint8> (payload.at(3));
                    offset = 4;
                }
                else
                {
                    dataType = static_cast <quint8> (payload.at(2));
                    offset = 3;
                }

                memcpy(&attributeId, payload.constData(), sizeof(attributeId));
                attributeId = qFromLittleEndian(attributeId);
                size = zclDataSize(dataType, payload, &offset);

                if (!size)
                {
                    logWarning << "Unrecognized attribute" << QString::asprintf("0x%04X", attributeId) << "data type" << QString::asprintf("0x%02X", dataType) << "received from device" << device->name() << "endpoint" << QString::asprintf("0x%02X", endpoint->id()) << "cluster" << QString::asprintf("0x%04X", clusterId) << "with payload:" << payload.mid(offset).toHex(':');
                    return;
                }

                parseAttribute(endpoint, clusterId, attributeId, dataType, payload.mid(offset, size));
                payload.remove(0, offset + size);
            }

            break;
        }

        case CMD_WRITE_ATTRIBUTES_RESPONSE:
        {
            if (clusterId == CLUSTER_IAS_ZONE && !payload.at(0))
            {
                endpoint->setZoneStatus(ZoneStatus::Enroll);
                interviewDevice(device);
            }

            break;
        }

        default:
            logWarning << "Unrecognized command" << QString::asprintf("0x%02X", commandId) << "received from device" << device->name() << "endpoint" << QString::asprintf("0x%02X", endpoint->id()) << "cluster" << QString::asprintf("0x%04X", clusterId) << "with payload:" << payload.toHex(':');
            break;
    }
}

void ZigBee::touchLinkReset(const QByteArray &ieeeAddress, quint8 channel)
{
    zclHeaderStruct header;
    touchLinkScanStruct payload;

    header.frameControl = FC_CLUSTER_SPECIFIC | FC_DISABLE_DEFAULT_RESPONSE;
    header.transactionId = m_transactionId++;
    header.commandId = 0x00;

    payload.transactionId = QRandomGenerator::global()->generate();
    payload.zigBeeInformation = 0x04;
    payload.touchLinkInformation = 0x12;

    if (!m_adapter->setInterPanChannel(channel))
        return;

    if (!m_adapter->extendedDataRequest(0xFFFF, 0xFE, 0xFFFF, 0x0C, CLUSTER_TOUCHLINK, QByteArray(reinterpret_cast <char*> (&header), sizeof(header)).append(QByteArray(reinterpret_cast <char*> (&payload), sizeof(payload)))))
    {
        logWarning << "TouchLink scan request failed, status code:" << QString::asprintf("%02X", m_adapter->dataRequestStatus());
        return;
    }

    header.commandId = 0x07;

    if (!m_adapter->extendedDataRequest(ieeeAddress, 0xFE, 0xFFFF, 0x0C, CLUSTER_TOUCHLINK, QByteArray(reinterpret_cast <char*> (&header), sizeof(header)).append(QByteArray(reinterpret_cast <char*> (&payload), sizeof(payload.transactionId)))))
    {
        logWarning << "TouchLink reset request failed, status code:" << QString::asprintf("%02X", m_adapter->dataRequestStatus());
        return;
    }

    logInfo << "TouchLink reset finished successfully";
}

void ZigBee::touchLinkScan(void)
{
    zclHeaderStruct header;
    touchLinkScanStruct payload;

    header.frameControl = FC_CLUSTER_SPECIFIC | FC_DISABLE_DEFAULT_RESPONSE;
    header.transactionId = m_transactionId++;
    header.commandId = 0x00;

    payload.transactionId = QRandomGenerator::global()->generate();
    payload.zigBeeInformation = 0x04;
    payload.touchLinkInformation = 0x12;

    logInfo << "TouchLink scan started...";

    for (m_interPanChannel = 11; m_interPanChannel <= 26; m_interPanChannel++)
    {
        if (!m_adapter->setInterPanChannel(m_interPanChannel))
            return;

        if (!m_adapter->extendedDataRequest(0xFFFF, 0xFE, 0xFFFF, 0x0C, CLUSTER_TOUCHLINK, QByteArray(reinterpret_cast <char*> (&header), sizeof(header)).append(QByteArray(reinterpret_cast <char*> (&payload), sizeof(payload)))))
        {
            logWarning << "TouchLink scan request failed, status code:" << QString::asprintf("%02X", m_adapter->dataRequestStatus());
            return;
        }
    }

    logInfo << "TouchLink scan finished successfully";
}

void ZigBee::blink(quint16 timeout)
{
    if (m_statusLedTimer->isActive() && m_statusLedPin == m_blinkLedPin)
        return;

    GPIO::setStatus(m_blinkLedPin, true);
    QTimer::singleShot(timeout, this, &ZigBee::updateBlinkLed);
}

void ZigBee::coordinatorReady(void)
{
    quint64 adapterAddress = qToBigEndian(qFromLittleEndian(m_adapter->ieeeAddress()));
    QByteArray ieeeAddress(reinterpret_cast <char*> (&adapterAddress), sizeof(adapterAddress));
    Device device(new DeviceObject(ieeeAddress));

    logInfo << "Coordinator ready, address:" << ieeeAddress.toHex(':').constData();

    for (auto it = m_devices->begin(); it != m_devices->end(); it++)
    {
        if (it.key() == ieeeAddress || it.value()->logicalType() == LogicalType::Coordinator)
            m_devices->erase(it++);

        if (it == m_devices->end())
            break;
    }

    device->setLogicalType(LogicalType::Coordinator);
    device->setName("HOMEd Coordinator");
    device->setInterviewFinished();

    m_devices->insert(ieeeAddress, device);
    m_devices->setAdapterType(m_adapter->type());
    m_devices->setAdapterVersion(m_adapter->version());

    connect(m_adapter, &Adapter::deviceJoined, this, &ZigBee::deviceJoined);
    connect(m_adapter, &Adapter::deviceLeft, this, &ZigBee::deviceLeft);
    connect(m_adapter, &Adapter::nodeDescriptorReceived, this, &ZigBee::nodeDescriptorReceived);
    connect(m_adapter, &Adapter::activeEndpointsReceived, this, &ZigBee::activeEndpointsReceived);
    connect(m_adapter, &Adapter::simpleDescriptorReceived, this, &ZigBee::simpleDescriptorReceived);
    connect(m_adapter, &Adapter::neighborRecordReceived, this, &ZigBee::neighborRecordReceived);
    connect(m_adapter, &Adapter::messageReveived, this, &ZigBee::messageReveived);
    connect(m_adapter, &Adapter::extendedMessageReveived, this, &ZigBee::extendedMessageReveived);

    m_queuesTimer->start(HANDLE_QUEUES_INTERVAL);
    m_neighborsTimer->start(UPDATE_NEIGHBORS_INTERVAL);
    m_adapter->setPermitJoin(m_devices->permitJoin());

    m_devices->storeStatus();
}

void ZigBee::permitJoinUpdated(bool enabled)
{
    if (enabled)
    {
        m_statusLedTimer->start(STATUS_LED_TIMEOUT);
        return;
    }

    m_statusLedTimer->stop();
    GPIO::setStatus(m_statusLedPin, m_statusLedPin != m_blinkLedPin);
}

void ZigBee::deviceJoined(const QByteArray &ieeeAddress, quint16 networkAddress)
{
    auto it = m_devices->find(ieeeAddress);

    if (it == m_devices->end())
    {
        logInfo << "Device" << ieeeAddress.toHex(':') << "joined network with address" << QString::asprintf("0x%04X", networkAddress);
        it = m_devices->insert(ieeeAddress, Device(new DeviceObject(ieeeAddress, networkAddress)));
    }
    else
        logInfo << "Device" << it.value()->name() << "rejoined network with address" << QString::asprintf("0x%04X", networkAddress);

    blink(500);

    if (it.value()->networkAddress() != networkAddress)
    {
        it.value()->setNetworkAddress(networkAddress);
        logInfo << "Device" << it.value()->name() << "network address updated";
    }

    if (!it.value()->interviewFinished() && !it.value()->timer()->isActive())
    {
        logInfo << "Device" << it.value()->name() << "interview started...";
        connect(it.value()->timer(), &QTimer::timeout, this, &ZigBee::interviewTimeout);
        it.value()->timer()->setSingleShot(true);
        interviewDevice(it.value());
    }

    it.value()->updateLastSeen();
    emit joinEvent(true);
}

void ZigBee::deviceLeft(const QByteArray &ieeeAddress)
{
    auto it = m_devices->find(ieeeAddress);

    if (it == m_devices->end())
        return;

    logInfo << "Device" << it.value()->name() << "left network";
    blink(500);

    m_devices->erase(it);
    m_devices->storeStatus();

    emit joinEvent(false);
}

void ZigBee::nodeDescriptorReceived(quint16 networkAddress, LogicalType logicalType, quint16 manufacturerCode)
{
    Device device = m_devices->byNetwork(networkAddress);

    if (device.isNull() || device->interviewFinished())
        return;

    device->setLogicalType(logicalType);
    device->setManufacturerCode(manufacturerCode);

    if (device->logicalType() == LogicalType::Router)
        logInfo << "Device" << device->name() << "is router";

    logInfo << "Device" << device->name() << "node descriptor received, manufacturer code:" << QString::asprintf("0x%04X", device->manufacturerCode());

    device->setNodeDescriptorReceived();
    device->updateLastSeen();

    interviewDevice(device);
}

void ZigBee::activeEndpointsReceived(quint16 networkAddress, const QByteArray data)
{
    Device device = m_devices->byNetwork(networkAddress);
    QList <QString> list;

    if (device.isNull() || device->interviewFinished())
        return;

    for (int i = 0; i < data.length(); i++)
    {
        quint8 endpointId = static_cast <quint8> (data.at(i));

        if (device->endpoints().find(endpointId) == device->endpoints().end())
            device->endpoints().insert(endpointId, Endpoint(new EndpointObject(endpointId, device)));

        list.append(QString::asprintf("0x%02X", endpointId));
    }

    logInfo << "Device" << device->name() << "active endpoints received:" << list.join(", ");

    device->setActiveEndpointsReceived();
    device->updateLastSeen();

    interviewDevice(device);
}

void ZigBee::simpleDescriptorReceived(quint16 networkAddress, quint8 endpointId, quint16 profileId, quint16 deviceId, const QList<quint16> &inClusters, const QList<quint16> &outClusters)
{
    Device device = m_devices->byNetwork(networkAddress);
    Endpoint endpoint;

    if (device.isNull() || device->interviewFinished())
        return;

    endpoint = getEndpoint(device, endpointId);

    endpoint->setProfileId(profileId);
    endpoint->setDeviceId(deviceId);

    endpoint->inClusters() = inClusters;
    endpoint->outClusters() = outClusters;

    logInfo << "Device" << device->name() << "endpoint" << QString::asprintf("0x%02X", endpoint->id()) << "simple descriptor received";

    device->updateLastSeen();
    interviewDevice(device);
}

void ZigBee::neighborRecordReceived(quint16 networkAddress, quint16 neighborAddress, quint8 linkQuality, bool start)
{
    Device device = m_devices->byNetwork(networkAddress);

    if (device.isNull())
        return;

    if (start)
    {
        logInfo << "Device" << device->name() << "neighbors list received";
        device->neighbors().clear();
    }

    if (m_devices->byNetwork(neighborAddress).isNull())
        return;

    device->neighbors().insert(neighborAddress, linkQuality);
    device->updateLastSeen();
}

void ZigBee::messageReveived(quint16 networkAddress, quint8 endpointId, quint16 clusterId, quint8 linkQuality, const QByteArray &data)
{
    Device device = m_devices->byNetwork(networkAddress);
    Endpoint endpoint;
    zclHeaderStruct header;
    QByteArray payload;

    if (device.isNull())
        return;

    endpoint = getEndpoint(device, endpointId);
    header.frameControl = static_cast <quint8> (data.at(0));
    blink(50);

    if (header.frameControl & FC_MANUFACTURER_SPECIFIC)
    {
        header.transactionId = static_cast <quint8> (data.at(3));
        header.commandId = static_cast <quint8> (data.at(4));
        payload = data.mid(5);
    }
    else
    {
        header.transactionId = static_cast <quint8> (data.at(1));
        header.commandId = static_cast <quint8> (data.at(2));
        payload = data.mid(3);
    }

    if (header.frameControl & FC_CLUSTER_SPECIFIC)
        clusterCommandReceived(endpoint, clusterId, header.transactionId, header.commandId, payload);
    else
        globalCommandReceived(endpoint, clusterId, header.commandId, payload);

    device->setLinkQuality(linkQuality);
    device->updateLastSeen();

    if (endpoint->dataUpdated())
    {
        endpoint->setDataUpdated(false);
        emit endpointUpdated(device, endpoint->id());
    }

    if (device->powerSource() != POWER_SOURCE_UNKNOWN && device->powerSource() != POWER_SOURCE_BATTERY && (header.frameControl & FC_CLUSTER_SPECIFIC || header.commandId == CMD_REPORT_ATTRIBUTES) && !(header.frameControl & FC_DISABLE_DEFAULT_RESPONSE))
    {
        defaultResponseStruct response;

        header.frameControl = FC_SERVER_TO_CLIENT | FC_DISABLE_DEFAULT_RESPONSE;
        header.commandId = CMD_DEFAULT_RESPONSE;

        response.commandId = header.commandId;
        response.status = 0x00;

        enqueueDataRequest(device, endpoint->id(), clusterId, QByteArray(reinterpret_cast <char*> (&header), sizeof(header)).append(QByteArray(reinterpret_cast <char*> (&response), sizeof(response))));
    }
}

void ZigBee::extendedMessageReveived(const QByteArray &ieeeAddress, quint8 endpointId, quint16 clusterId, quint8 linkQuality, const QByteArray &data)
{
    Q_UNUSED(endpointId)
    Q_UNUSED(linkQuality)

    const zclHeaderStruct *header = reinterpret_cast <const zclHeaderStruct*> (data.constData());

    if (clusterId == CLUSTER_TOUCHLINK && header->commandId == 0x01)
    {
        logInfo << "TouchLink scan response received from device" << ieeeAddress.toHex(':') << "at channel" << m_interPanChannel;
        return;
    }

    logWarning << "Unrecognized extended message received from" << ieeeAddress.toHex(':') << "endpoint" << QString::asprintf("0x%02X", endpointId) << "cluster" << QString::asprintf("0x%04X", clusterId) << "with payload:" << data.toHex(':');
}

void ZigBee::interviewTimeout(void)
{
    DeviceObject *device = reinterpret_cast <DeviceObject*> (sender()->parent());
    logWarning << "Device" << device->name() << "interview timed out";
}

void ZigBee::pollAttributes(void)
{
    EndpointObject *endpoint = reinterpret_cast <EndpointObject*> (sender()->parent());

    for (int i = 0; i < endpoint->polls().count(); i++)
    {
        const Poll &poll = endpoint->polls().at(i);
        readAttributes(endpoint->device(), endpoint->id(), poll->clusterId(), poll->attributes());
    }
}

void ZigBee::updateNeighbors(void)
{
    for (auto it = m_devices->begin(); it != m_devices->end(); it++)
    {
        if (it.value()->logicalType() == LogicalType::EndDevice || m_neighborsQueue.contains(it.value()))
            continue;

        m_neighborsQueue.enqueue(it.value());
    }
}

void ZigBee::handleQueue(void)
{
    while (!m_bindQueue.isEmpty())
    {
        BindRequest request = m_bindQueue.dequeue();

        if (m_adapter->bindRequest(request->device()->networkAddress(), request->device()->ieeeAddress(), request->endpointId(), request->clusterId(), request->dstAddress(), request->dstEndpointId(), request->unbind()))
        {
            if (!request->dstAddress().isEmpty())
                logInfo << "Device" << request->device()->name() << (request->unbind() ? "unbinding" : "binding") << "finished succesfully";

            continue;
        }

        logWarning << "Device" << request->device()->name() << "endpoint" << QString::asprintf("0x%02X", request->endpointId()) << "cluster" << QString::asprintf("0x%04X", request->clusterId()) << (request->unbind() ? "unbinding" : "binding") << "failed";
    }

    while (!m_dataQueue.isEmpty())
    {
        DataRequest request = m_dataQueue.dequeue();

        if (m_adapter->dataRequest(request->device()->networkAddress(), request->endpointId(), request->clusterId(), request->data()))
        {
            if (!request->name().isEmpty())
                logInfo << "Device" << request->device()->name() << request->name().toUtf8().constData() << "finished successfully";

            continue;
        }

        logWarning << "Device" << request->device()->name() << (!request->name().isEmpty() ? request->name().toUtf8().constData() : "data request") << "failed, status code:" << QString::asprintf("%02X", m_adapter->dataRequestStatus());
    }

    if (!m_interviewQueue.isEmpty())
        interviewRequest(m_interviewQueue.dequeue());

    if (!m_neighborsQueue.isEmpty())
    {
        Device device = m_neighborsQueue.dequeue();
        m_adapter->lqiRequest(device->networkAddress());
    }
}

void ZigBee::updateStatusLed(void)
{
    GPIO::setStatus(m_statusLedPin, !GPIO::getStatus(m_statusLedPin));
}

void ZigBee::updateBlinkLed(void)
{
    GPIO::setStatus(m_blinkLedPin, false);
}
