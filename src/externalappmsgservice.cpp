#include <QDBusInterface>
#include <QDebug>
#include <utility>
#include <algorithm>
#include <optional>
#include <cstring>
#include <cassert>

#include "externalappmsgservice.h"
#include "characteristic.h"
#include "common.h"


// We use a simple custom protocol here to transmit payloads that are potentially
// larger than the configured BLE MTU allows. It splits messages into chunks and adds
// metadata to let the receiver know how to stitch the chunks back together.
// The payloads we send over GATT are structured as follows:
//
// First comes a byte that is the "message counter". This counter is the same value for
// all GATT chunk transmissions. That way, the receiver knows when received chunks belong
// to the same message and when a new message starts. It also solves the problem of partial
// messages: If for some reason a message is only partially transmitted before another one
// gets sent, the receiver will see chunks come in with a different counter value. When
// this happens, the receiver knows that it needs to discard any previously received chunk
// that used the old counter value. The counter value is incremented here after fully
// sending the message. When the counter is at 255 and is incremented, it wraps around
// back to 0.
//
// Next comes a 16 bit little endian integer that contains the chunk's message offset.
// It specifies where within the message the chunk got its data from.
//
// This is followed by another 16 bit little endian integer that is the total message size
// minus 1. This means that (a) the maximum message size and (b) messages must have at
// least 1 byte.
//
// After that comes the actual chunk payload.


namespace {


template<typename Predicate>
bool checkString(QString const &str, QString const &name, Predicate const &predicate)
{
	if (std::find_if(str.begin(), str.end(), predicate) != str.end()) {
		qCritical() << QString("Invalid %1 \"%2\"").arg(name).arg(str);
		return false;
	} else
		return true;
}


struct MessageDetails
{
	// Identifies the source (= the app) that produced this message.
	// This can only contain alphanumeric characters and the "." character.
	QString m_source;
	// Destination for this message. This is appended to the base DBus
	// service name and object path for sending out a DBus call.
	// This can only contain alphanumeric characters, and must not start
	// with "interfaces".
	QString m_destination;
	// Message payload. This can contain any bytes, including newline and
	// carriage characters and non-printable characters.
	QByteArray m_payload;

	enum class PartIndices {
		SOURCE = 0,
		DESTINATION = 1,
		PAYLOAD = 2,

		LAST_INDEX = 2
	};

	bool fromBytes(QByteArray const &bytes)
	{
		int curPartIndex = 0;
		int substringStartPosition = 0;

		for (int position = 0; (position < bytes.length()) && (curPartIndex < int(PartIndices::LAST_INDEX)); ++position) {
			if (bytes[position] == '\n') {
				QString substring(bytes.mid(substringStartPosition, position - substringStartPosition));

				switch (PartIndices(curPartIndex)) {
					case PartIndices::SOURCE:
						if (!checkString(substring, "source", [](auto ch) { return !(ch.isLetterOrNumber() || (ch == '.')); }))
							return false;
						m_source = std::move(substring);
						break;

					case PartIndices::DESTINATION:
						if (!checkString(substring, "destination", [](auto ch) { return !(ch.isLetterOrNumber()); }))
							return false;
						if (substring.startsWith("interfaces")) {
							qCritical() << "Invalid destination: must not start with \"interfaces\"";
							return false;
						}
						m_destination = std::move(substring);
						break;

					default:
						break;
				}

				curPartIndex++;
				substringStartPosition = position + 1;
			}
		}

		if (PartIndices(curPartIndex) != PartIndices::LAST_INDEX) {
			qCritical()
				<< "Invalid message contents; expected"
				<< (int(PartIndices::LAST_INDEX) + 1)
				<< "subtrings, got" << (int(curPartIndex) + 1);
			return false;
		}

		m_payload = bytes.mid(substringStartPosition);

		return true;
	}
};


} // unnamed namespace end


class PushMessageChrc : public Characteristic
{
public:
	PushMessageChrc(QDBusConnection bus, int index, Service *service) : Characteristic(bus, index, EXT_APP_PUSH_UUID, {"encrypt-authenticated-write"}, service) {}

public slots:
	void WriteValue(QByteArray chunk, QVariantMap)
	{
		// A chunk always contains at least 5 bytes:
		// The message counter (1 byte), chunk offset (1 16-bit int), message size (1 16-bit int).
		// A chunk smaller than that is invalid.
		if (chunk.size() < 5) {
			qWarning() << "Got invalid chunk; if any previous chunks got received, then they will be discarded now";
			discardReceivedData();
			return;
		}

		quint8 messageCounter = chunk[0];

		bool isNewMessage = (m_lastMessageCounter == std::nullopt) || ((*m_lastMessageCounter) != messageCounter);

		if (isNewMessage)
		{
			if (m_lastMessageCounter) {
				qDebug() << "Message counter changed from" << int(*m_lastMessageCounter)
				         << "to" << int(messageCounter) << " -> a new message just started";
			} else {
				qDebug() << "Got first message; counter is" << int(messageCounter);
			}

			// Get rid of any partially received data - it belongs to a message
			// that will not be finished (since the counter changed).
			discardReceivedData();

			m_lastMessageCounter = messageCounter;
		}

		quint16 chunkOffset = chunk[1] | ((quint16)(chunk[2]) << 8);
		quint16 messageSize = (chunk[3] | ((quint16)(chunk[4]) << 8)) + 1;
		qsizetype chunkSize = chunk.size() - 5; // -5 to exclude the message counter, chunk offset, and message size

		m_numReceivedMessageBytes += chunkSize;

		qDebug() << "Got chunk:"
		         << "chunk offset:" << chunkOffset
		         << "chunk size:" << chunkSize
		         << "total num received bytes:" << m_numReceivedMessageBytes
		         << "total message size:" << messageSize
		         << "message counter:" << messageCounter;

		if (m_messageBytes.size() != messageSize)
			m_messageBytes.resize(messageSize);

		assert(chunkSize <= (messageSize - chunkOffset));
		std::memcpy(
			m_messageBytes.data() + chunkOffset,
			chunk.data() + 5, // +5 to skip the message counter, chunk offset, and message size
			chunkSize
		);

		if (m_numReceivedMessageBytes >= messageSize)
			processMessage();
	}

private:
	void processMessage()
	{
		MessageDetails msgDetails;
		if (!msgDetails.fromBytes(m_messageBytes))
			return;

		qDebug() << "Got message:"
				 << "source:" << msgDetails.m_source
				 << "destination:" << msgDetails.m_destination
				 << "; payload contains" << msgDetails.m_payload.size() << "byte(s)";

		static QDBusInterface extAppMsgIFace(
			QString(EXT_APP_MSG_SERVICE_NAME_BASE) + "." + msgDetails.m_destination,
			QString(EXT_APP_MSG_PATH_BASE),
			EXT_APP_MSG_MAIN_IFACE
		);

		QDBusMessage reply = extAppMsgIFace.call(
			QDBus::AutoDetect,
			"pushMessage",
			msgDetails.m_source,
			msgDetails.m_payload
		);
		if(reply.type() == QDBusMessage::ErrorMessage)
			qCritical() << "PushMessageChrc::WriteValue: D-Bus Error:" << reply.errorMessage();

		discardReceivedData();
	}

	void discardReceivedData()
	{
		m_lastMessageCounter = std::nullopt;
		m_messageBytes.clear();
		m_numReceivedMessageBytes = 0;
	}

	std::optional<quint8> m_lastMessageCounter;
	QByteArray m_messageBytes;
	qsizetype m_numReceivedMessageBytes;
};


ExternalAppMsgService::ExternalAppMsgService(int index, QDBusConnection bus, QObject *parent) : Service(bus, index, EXT_APP_UUID, parent)
{
	addCharacteristic(new PushMessageChrc(bus, 0, this));
}
