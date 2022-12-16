#ifndef EXTERNALAPPMSGSERVICE_H
#define EXTERNALAPPMSGSERVICE_H

#include <QObject>

#include "service.h"

class ExternalAppMsgService : public Service
{
    Q_OBJECT
public:
    explicit ExternalAppMsgService(int index, QDBusConnection bus, QObject *parent = 0);
};

#endif // EXTERNALAPPMSGSERVICE_H
